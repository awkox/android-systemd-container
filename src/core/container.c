#include "asc.h"

/* ---------------------------------------------------------------------------
 * External Command Lock - CLI-only ownership
 *
 * The lock represents exactly ONE thing: an external CLI command is actively
 * managing this container. ONLY the CLI parent creates/removes locks.
 * The monitor is READ-ONLY for locks.
 * ---------------------------------------------------------------------------*/

/* 保存当前进程持有的锁 FD 和路径，解决进程内多次申请锁的重入问题 */
static int active_lock_fd = -1;
static char active_lock_path[PATH_MAX] = "";

/* 构建锁路径并进行防御性截断。精度：
 * 2048 (lock_dir) + 256 (name) + 5 (.lock) = 2309 < PATH_MAX (4096)
 * 这样可以防止格式截断警告，同时确保路径永远不会溢出。 */
static int get_lock_path(const char *name, char *buf, const size_t size) {
  if (!name || !buf || size == 0 || !validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));
  const int r =
      snprintf(buf, size, "%.2048s/%.256s.lock", get_lock_dir(), safe_name);
  return r > 0 && (size_t)r < size ? 0 : -1;
}

/* Create external command lock - ONLY called by CLI parent.
 * Uses POSIX record locks (fcntl) for automatic kernel cleanup.
 * Returns: 0 on success, -1 if lock already held by a live process. */
static int acquire_external_lock(const char *name) {
  /* Re-entrancy: 如果当前进程已经持有锁（例如 restart 流程），直接返回成功 */
  if (active_lock_fd >= 0)
    return 0;

  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return -1;

  /* 获取写锁必须使用可写模式打开 */
  const int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  struct flock fl = {
    .l_type = F_WRLCK,
    .l_whence = SEEK_SET,
  };

  /* 尝试非阻塞 POSIX 记录锁 */
  if (fcntl(fd, F_SETLK, &fl) == 0) {
    /* 获取成功。依然写入 PID，仅用于后续可能的纯文本 Debug */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(fd, 0) == 0) {
      write_all(fd, pid_str, strlen(pid_str));
    }
    
    /* 记录 FD，进程退出或关闭该 FD 时，内核会自动释放锁 */
    active_lock_fd = fd;
    safe_strncpy(active_lock_path, lock_path, sizeof(active_lock_path));
    return 0;
  }

  /* 锁被其他进程占用，向内核查询持有者的 PID 并打印 */
  if (errno == EACCES || errno == EAGAIN) {
    fl.l_type = F_WRLCK;
    if (fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK) {
      log_warn("Cannot acquire lock: held by process %d", fl.l_pid);
    }
  }

  close(fd);
  return -1;
}

/* Release external command lock - ONLY called by CLI parent. */
static void release_external_lock(void) {
  if (active_lock_fd >= 0) {
    /* 
     * 在关闭 FD 前先 unlink，防止其他排队的进程获取到一个即将被删除的孤儿文件的锁。
     * 这保持了 lock 目录的干净。
     */
    if (active_lock_path[0]) {
      unlink(active_lock_path);
    }
    
    /* 原子操作：关闭 FD 的瞬间，内核释放关联的 POSIX 锁 */
    close(active_lock_fd);
    active_lock_fd = -1;
    active_lock_path[0] = '\0';
  }
}

/* Check if external command lock exists - called by monitor (READ ONLY).
 * Returns: 1 if lock exists and holder is alive, 0 otherwise. */
bool is_external_lock_active(const char *name) {
  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return false;

  auto_close const int fd = open(lock_path, O_RDONLY | O_CLOEXEC);
  return !(fd < 0);
}

void cleanup_container_resources(cfg_t *cfg,
                                 const bool skip_unmount, const bool force_cleanup) {
  /* Flush filesystem buffers (skip if force cleanup - sync can hang on
   * zombie-held fs) */
  if (!force_cleanup)
    sync();

  /* 1. Cleanup firmware path (hw_access mode only; skip on force-cleanup
   * since accessing a zombie-held mount can hang).
   * Use cfg->conf.img_mount_point directly - it is already fully resolved and valid. */
  if (!force_cleanup && cfg->conf.hw_access && cfg->conf.img_mount_point[0]) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 2. Handle Volatile Overlay Cleanup (upper/work/merged)
   * This MUST happen before unmounting the lower image mount.
   * When force_cleanup, use detach+force unmount to avoid hangs. */
  if (cfg->conf.volatile_mode) {
    if (force_cleanup) {
      /* Force path: skip sync, just detach everything */
      char merged[PATH_MAX + 32];
      snprintf(merged, sizeof(merged), "%s/merged", cfg->rt.volatile_dir);
      umount2(merged, MNT_DETACH | MNT_FORCE);
      umount2(cfg->rt.volatile_dir, MNT_DETACH | MNT_FORCE);
      /* Best-effort directory removal */
      remove_recursive(cfg->rt.volatile_dir);
      cfg->rt.volatile_dir[0] = '\0';
    } else {
      cleanup_volatile_overlay(&cfg->rt);
    }
  }

  /* 4. Handle rootfs image unmount */
  char mount_point[PATH_MAX] = "";
  if (cfg->conf.img_mount_point[0]) {
    safe_strncpy(mount_point, cfg->conf.img_mount_point, sizeof(mount_point));
  }

  if (mount_point[0] && !skip_unmount) {
    if (force_cleanup) {
      /* Force path: detach+force unmount, no sync, no retry loops */
      umount2(mount_point, MNT_DETACH | MNT_FORCE);
      rmdir(mount_point); /* best-effort */
    } else {
      /* Explicitly call unmount wrapper. It handles its own logging. */
      unmount_rootfs_img(mount_point, cfg->rt.foreground);
    }
  }

  /* 5. Remove tracking info.
   * For restart (skip_unmount), preserve locks so start can detect handoff. */
  if (!skip_unmount) {
    /* Stale lock cleanup is handled by acquire_external_lock and
     * is_external_lock_active. Monitor only does resource cleanup
     * if no external lock is active. */
  }

  /* Cgroup 子树清理：删除 /sys/fs/cgroup/asc/<name>/ 目录。
   * All container processes are dead by now so every leaf is empty and
   * the bottom-up rmdir walk always succeeds.  Skipped on restart
   * (skip_unmount=1) so the monitor's cgroup context stays intact for
   * the next boot cycle. */
  if (!skip_unmount) {
    cgroup_cleanup_container(cfg->conf.container_name);
  }
}

bool is_valid_container_pid(const pid_t pid) {
  char path[PATH_MAX];

  /* 主要标记：容器内必须存在 /run/asc。这是由本项目在引导时写入的唯一权威标记
   * We do NOT require /run/systemd/container - Alpine/runit/openrc never
   * write that file, causing scan to be blind to non-systemd distros. */
  if (build_proc_root_path(pid, FORK_MARKER, path, sizeof(path)) < 0)
    return false;
  if (access(path, F_OK) != 0)
    return false;

  /* Secondary check: process must be the init (PID 1) of its namespace.
   * This is more robust than checking cmdline for "init" which distros
   * like Void Linux (runit) or Alpine may not provide. */
  if (!is_container_init(pid))
    return false;

  return true;
}

int start_rootfs(cfg_t *cfg) {
  bool has_side_effects = false;
  bool lock_acquired = false;

  /* 0. Early restart detection: check for external lock from previous stop
   *    command to detect a preserved mount for reuse. */
  if (cfg->conf.container_name[0]) {
    char lock_path[PATH_MAX];
    if (get_lock_path(cfg->conf.container_name, lock_path, sizeof(lock_path)) == 0 &&
        access(lock_path, F_OK) == 0) {
      /* This looks like a restart handoff - take ownership of the lock */
      if (acquire_external_lock(cfg->conf.container_name) == 0) {
        lock_acquired = true;

        /* Try to reuse existing mount from config */
        if (cfg->conf.img_mount_point[0] && is_mountpoint(cfg->conf.img_mount_point)) {
        } else {
          /* Mount not active - remove invalid lock */
          release_external_lock();
          lock_acquired = false;
        }
      }
    }
  }

  /* 1. Name Uniqueness Check
   * We no longer auto-generate or increment names. The name must be provided
   * by the user and it must be unique. */
  if (!lock_acquired) {
    pid_t existing_pid = 0;
    if (is_container_running(cfg, &existing_pid)) {
      log_error("Container name '%s' is already in use by PID %d.",
                cfg->conf.container_name, existing_pid);
      goto cleanup;
    }
  }

  /* 2. Preparation */
  ensure_runtime();

  /* 0a. Resolve any symlinks in rootfs image path to canonical absolute paths.
   *     This prevents symlink-based attacks and ensures that all subsequent
   *     operations use the intended location. */
  if (cfg->conf.rootfs_img_path[0]) {
    auto_free char *abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (!abs_path || access(abs_path, F_OK) != 0) {
      log_error("Failed to resolve rootfs image path '%s': %s",
                abs_path ? abs_path : cfg->conf.rootfs_img_path, strerror(errno));
      goto cleanup;
    }
    safe_strncpy(cfg->conf.rootfs_img_path, abs_path, sizeof(cfg->conf.rootfs_img_path));
  }

  /* if foreground was requested but we have no interactive terminal (piped,
   * scripted, config foreground=1, etc.), flip the switch once here and warn
   * once. Covers both CLI and daemon paths. */
  if (cfg->rt.foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->rt.foreground = 0;
    log_warn("No interactive terminal - foreground mode disabled, running in "
             "background.");
  }

  print_cgroup_status(cfg);

  has_side_effects = true;

  /* 2. Mount rootfs image (using the resolved name) */
  if (cfg->conf.rootfs_img_path[0] && !lock_acquired) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, cfg->conf.img_mount_point,
                         sizeof(cfg->conf.img_mount_point), cfg->conf.container_name) < 0) {
      goto cleanup; /* 失败时跳转到清理流程，下方 cleanup 函数会自动解除绑定 */
    }
  }

  /* 2a. Verify init binary exists before any side effects (NAT, config save).
   * The image is now mounted at img_mount_point. */
  {
    char init_path[PATH_MAX * 2];
    char rootfs_norm[PATH_MAX];
    if (cfg->conf.img_mount_point[0])
      safe_strncpy(rootfs_norm, cfg->conf.img_mount_point, sizeof(rootfs_norm));
    else {
      log_error("Rootfs image mount point not available.");
      return -1;
    }
    size_t rlen = strlen(rootfs_norm);
    if (rlen > 0 && rootfs_norm[rlen - 1] == '/')
      rootfs_norm[rlen - 1] = '\0';

    const char *init_bin =
        cfg->conf.custom_init[0] ? cfg->conf.custom_init : DEFAULT_INIT;
    snprintf(init_path, sizeof(init_path), "%.*s%s",
             (int)(sizeof(init_path) - strlen(init_bin) - 1), rootfs_norm,
             init_bin);
    struct stat st;
    if (lstat(init_path, &st) != 0) {
      log_error("Init binary not found: %s", init_path);
      log_error("Please ensure the rootfs path is correct and contains %s.",
                init_bin);
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
    /* Absolute symlinks resolve correctly inside the container after
     * pivot_root, so skip the X_OK check for symlinks. */
    if (!S_ISLNK(st.st_mode) && access(init_path, X_OK) != 0) {
      log_error("Init binary is not executable: %s", init_path);
      log_error("Ensure it has executable permissions.");
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
  }

  /* 3. Early pre-flight for volatile mode (before any host changes) */
  if (check_volatile_mode(&cfg->conf) < 0) {
    goto cleanup;
  }

  {
    char active_uuids[MAX_CONTAINERS][UUID_LEN + 1];
    int uuid_count = collect_active_uuids(active_uuids, MAX_CONTAINERS);
    bool need_new = cfg->conf.uuid[0] == '\0';
    if (!need_new) {
      for (int _i = 0; _i < uuid_count; _i++) {
        if (strcmp(cfg->conf.uuid, active_uuids[_i]) == 0) {
          need_new = true;
          break;
        }
      }
    }
    if (need_new)
      generate_uuid(cfg->conf.uuid, sizeof(cfg->conf.uuid));
  }

  /* Persist UUID to config immediately
   * so disk always matches the running container. CLI overrides (e.g. -f)
   * are already in cfg at this point since start_rootfs() is called after
   * argument parsing. */
  if (cfg->rt.config_file[0]) {
    bool was_new = !cfg->rt.config_file_existed;
    if (config_save(cfg->rt.config_file, cfg) < 0) {
      log_error("Failed to persist configuration to '%s': %s", cfg->rt.config_file,
                strerror(errno));
      goto cleanup;
    }
    if (was_new) {
      log_info("Configuration persisted to %s", cfg->rt.config_file);
    }
  }

  /* Mirror to workspace so 'start -n <n>' works later without --conf */
  if (config_save_by_name(cfg->conf.container_name, cfg) < 0) {
    log_warn("Failed to mirror configuration to workspace for '%s': %s",
             cfg->conf.container_name, strerror(errno));
  }

  /* Pre-populate volatile_dir for monitor cleanup (actual overlay setup
   * happens inside internal_boot's isolated mount namespace) */
  if (cfg->conf.volatile_mode) {
    snprintf(cfg->rt.volatile_dir, sizeof(cfg->rt.volatile_dir),
             "%s/" RUNTIME_VOLATILE_SUBDIR "/%s", get_runtime_dir(),
             cfg->conf.container_name);
  }

  /* 4. Parent-side PTY allocation (LXC Model) */

  /* Firmware path - hw_access mode only.
   * The image is mounted at img_mount_point.  firmware_path_add() internally
   * checks that /lib/firmware exists in the rootfs before touching the sysfs
   * node. */
  if (cfg->conf.hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_add(fw_path);
  }

  fix_host_ptys();

  if (terminal_create(&cfg->rt.console) < 0) {
    log_error("Failed to allocate console PTY");
    goto cleanup;
  }

  /* Propagate the host terminal's window size to the console PTY master
   * so the slave (which becomes /dev/console) has correct dimensions
   * from the very start of boot. This prevents misaligned output during
   * the window between PTY creation and the console_monitor_loop startup.
   * Without this, 'sudo poweroff' output is misaligned for the first
   * ~10 lines because sudo resets/queries the terminal size and finds
   * a {0,0} winsize on the PTY slave. */
  if (isatty(STDIN_FILENO)) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(cfg->rt.console.master, TIOCSWINSZ, &ws);
  }

  /* 5. Pipe for synchronization */
  int sync_pipe[2] = {-1, -1};
  if (pipe(sync_pipe) < 0) {
    log_error("pipe failed: %s", strerror(errno));
    goto cleanup;
  }

  /* Set FD_CLOEXEC on both ends of sync_pipe */
  fcntl(sync_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl(sync_pipe[1], F_SETFD, FD_CLOEXEC);

  /* Record start time before fork so monitor and virtualize_update share it */
  clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

  /* 7. Fork Monitor Process */
  pid_t monitor_pid = fork();
  if (monitor_pid < 0) {
    close(sync_pipe[0]);
    close(sync_pipe[1]);
    log_error("fork failed: %s", strerror(errno));
    goto cleanup;
  }

  if (monitor_pid == 0) {
    close(sync_pipe[0]);
    monitor_run(cfg, sync_pipe[1]);
    /* monitor_run never returns */
    _exit(EXIT_FAILURE);
  }

  /* PARENT PROCESS */
  close(sync_pipe[1]);

  /* Wait for Monitor to send child PID */
  if (read(sync_pipe[0], &cfg->rt.container_pid, sizeof(pid_t)) != sizeof(pid_t)) {
    log_error("Monitor failed to send container PID.");
    if (lock_acquired)
      release_external_lock();
    goto cleanup;
  }
  close(sync_pipe[0]);
  sync_pipe[0] = -1;

  log_info("Container started with PID %d (Monitor: %d)", cfg->rt.container_pid,
           monitor_pid);

  /* Log volatile mode */
  if (cfg->conf.volatile_mode)
    log_info("Entering volatile mode (OverlayFS)...");

  /* 9. Done - container is running, metadata is in /proc/<pid>/environ */
  if (cfg->conf.img_mount_point[0]) {
    /* Ensure mount point is persisted in config for restart recovery */
    cfg_t save_cfg = *cfg;
    config_save_by_name(cfg->conf.container_name, &save_cfg);
  }

  /* 10. Foreground or background finish */
  if (cfg->rt.foreground) {
    if (lock_acquired) {
      release_external_lock();
    }

    int ret = console_monitor_loop(cfg->rt.console.master, monitor_pid, cfg);
    return ret;
  } else {
    /* Wait for container to finish pivot_root before showing info.
     * The boot sequence writes /run/ds-fork after pivot_root,
     * so we poll for it via /proc/<pid>/root/run/ds-fork. */
    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "/proc/%d/root/run/" PROJECT_NAME,
             cfg->rt.container_pid);
    bool booted = false;
    for (int i = 0; i < 50; i++) { /* 5 seconds max */
      if (access(marker, F_OK) == 0) {
        booted = true;
        break;
      }
      /* If the container PID is already dead, stop polling */
      if (kill(cfg->rt.container_pid, 0) < 0 && errno == ESRCH)
        break;
      usleep(100000); /* 100ms */
    }

    if (!booted) {
      log_error("Container failed to boot correctly.");
      /* If pid is still alive, we might want to kill it, but monitor usually
       * handles this. Let's just return error so parent doesn't report
       * success.
       */
      goto cleanup;
    }

    show_info(cfg, true);
    log_info("Container '%s' is running in background.", cfg->conf.container_name);
  }

  if (lock_acquired)
    release_external_lock();

  return 0;

cleanup:
  /* Centralized host-side cleanup IF we are returning error.
   * This ensures image mounts and tracking files are reverted on fatal boot
   * errors. Only execute if we successfully crossed the point of creating
   * effects. */
  if (has_side_effects) {
    cleanup_container_resources(cfg, false, true /* force */);
  }
  if (lock_acquired)
    release_external_lock();

  if (cfg->rt.console.master >= 0) {
    close(cfg->rt.console.master);
    cfg->rt.console.master = -1;
  }
  if (sync_pipe[0] >= 0)
    close(sync_pipe[0]);
  if (sync_pipe[1] >= 0)
    close(sync_pipe[1]);

  return -1;
}

static int stop_rootfs_with_timeout(cfg_t *cfg, const bool skip_unmount,
                             int timeout_seconds) {
  if (timeout_seconds < 0)
    timeout_seconds = STOP_TIMEOUT;

  /* Acquire external command lock FIRST */
  if (acquire_external_lock(cfg->conf.container_name) != 0) {
    log_error("Cannot stop '%s': another command is managing this container",
              cfg->conf.container_name);
    log_error("Wait for the other operation to complete, or use '" PROJECT_NAME
              " "
              "show' to check status");
    return -1;
  }

  pid_t pid = 0;
  if (!is_container_running(cfg, &pid) || pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->conf.container_name);
    release_external_lock();
    return -1;
  }

  log_info("Stopping container '%s' (PID %d)...", cfg->conf.container_name, pid);

  /* Safe Metadata Capture: Read mount path from /proc/<pid>/environ
   * before shutdown to preserve it for cleanup if container dies. */
  if (cfg->conf.img_mount_point[0] == '\0') {
    read_proc_environ(pid, "RUNTIME_MOUNT_PATH", cfg->conf.img_mount_point,
                      sizeof(cfg->conf.img_mount_point));
  }

  /* 1. Send shutdown signal. */
  kill(pid, SIGRTMIN + 3); /* SIGRTMIN+3 */

  log_info(
      "Waiting for graceful shutdown (this may take up to %d seconds)...",
      timeout_seconds);

  /* 2. Wait for exit */
  bool stopped = false;
  for (int i = 0; i < timeout_seconds * 5; i++) {
    if (kill(pid, 0) < 0) {
      if (errno == ESRCH) {
        stopped = true;
        break;
      }
    }
    usleep(RETRY_DELAY_US);
  }

  /* 3. Force kill if still running */
  bool unkillable = false;
  if (!stopped) {
    log_warn("Graceful stop timed out, sending SIGKILL...");
    kill(pid, SIGKILL);

    /*
     * Wait up to 5 seconds for the kernel to clean up the process.
     * We don't use blocking waitpid() because we aren't the parent,
     * and we want a timeout to prevent hanging on unkillable PIDs.
     */
    bool killed = false;
    for (int j = 0; j < 25; j++) { /* 5 seconds total */
      if (kill(pid, 0) < 0 && errno == ESRCH) {
        killed = true;
        break;
      }
      usleep(RETRY_DELAY_US);
    }

    if (!killed) {
      unkillable = true;
      log_error("Container PID %d is in an unkillable state!", pid);
      log_warn("This often happens on old Android kernels due to zombie "
               "processes.\nPlease restart your device to clear it.");
      log_warn("Proceeding with best-effort host cleanup (no sync)...");
    }
  }

  /* 4. Firmware cleanup (hw_access mode only).
   * Skip when unkillable - accessing zombie-held rootfs can hang. */
  if (cfg->conf.img_mount_point[0] && !unkillable && cfg->conf.hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 5. Complete resource cleanup. */
  cleanup_container_resources(cfg, skip_unmount, unkillable);

  if (!cfg->rt.foreground)
    log_info("Container '%s' stopped.", cfg->conf.container_name);

  /* Release lock ONLY if this is a final stop.
   * For restarts (skip_unmount=1), keep lock alive as handoff. */
  if (!skip_unmount) {
    release_external_lock();
  }

  return 0;
}

int stop_rootfs(cfg_t *cfg, const bool skip_unmount) {
  return stop_rootfs_with_timeout(cfg, skip_unmount, STOP_TIMEOUT);
}

static const char *get_architecture(void) {
  static struct utsname uts;
  if (uname(&uts) != 0)
    return "unknown";
  return uts.machine;
}

static void parse_pretty_name(FILE *fp, char *buf, const size_t size) {
  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
      char *val = line + 12;
      size_t len = strlen(val);
      while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '"'))
        val[--len] = '\0';
      if (val[0] == '"') {
        val++;
        len--;
      }
      if (len >= size)
        len = size - 1;
      snprintf(buf, size, "%.*s", (int)len, val);
      return;
    }
  }
}

static void get_os_pretty(const char *osrelease_path, char *buf, const size_t size) {
  if (!buf || size == 0)
    return;
  buf[0] = '\0';

  auto_fclose FILE *fp = fopen(osrelease_path, "r");
  if (!fp)
    return;

  parse_pretty_name(fp, buf, size);
}

int show_info(cfg_t *cfg, const bool trust_cfg_pid) {
  /* Case 1: No container name specified - try auto-resolution or listing */
  if (cfg->conf.container_name[0] == '\0') {
    log_error("Container name is missing.");
    return 0;
  }

  /* Now we have a container name. Ensure its config is loaded from the source
   * of truth (container.config) so we show accurate feature info without
   * expensive live probing. */
  if (!trust_cfg_pid) {
    config_load_by_name(cfg->conf.container_name, cfg);
  }

  /* Case 2: Validate running status */
  pid_t pid = 0;
  if (trust_cfg_pid && cfg->rt.container_pid > 0) {
    /* Trust the PID we just got from the sync pipe.
     * We assume it's running because parent waited for boot marker. */
    pid = cfg->rt.container_pid;
  } else {
    /* For other calls (e.g., info command), read and validate from pidfile. */
    is_container_running(cfg, &pid);
  }

  if (pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->conf.container_name);
    return -1;
  }

  /* Success - print Host and detailed Container info */
  if (cfg->rt.format_output) {
    const char *arch = get_architecture();
    printf("HOST_ARCH=%s\n", arch);
    printf("CONTAINER_NAME=%s\n", cfg->conf.container_name);
    printf("CONTAINER_PID=%d\n", pid);

    char pretty[256];
    char osr_path[PATH_MAX];
    if (build_proc_root_path(pid, OS_RELEASE, osr_path,
                             sizeof(osr_path)) == 0) {
      get_os_pretty(osr_path, pretty, sizeof(pretty));
      if (pretty[0])
        printf("CONTAINER_OS=%s\n", pretty);
    }

    if (!trust_cfg_pid) {
      const long uptime_sec = get_container_uptime(pid);
      if (uptime_sec >= 0) {
        char uptime_str[128];
        format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));
        printf("CONTAINER_UPTIME=%s\n", uptime_str);
      }
    }

    printf("ISOLATION_NETWORK=%d\n", cfg->conf.isolation_network);

    if (cfg->conf.hw_access)
      printf("HW_ACCESS=full\n");
    else if (cfg->conf.gpu_mode)
      printf("HW_ACCESS=GPU\n");
    else
      printf("HW_ACCESS=none\n");

    printf("VOLATILE_MODE=%d\n", cfg->conf.volatile_mode);
    printf("FORCE_CGROUP_V1=%d\n", cfg->conf.force_cgroupv1);
    printf("DEADLOCK_SHIELD=%d\n", cfg->conf.block_nested_ns);

    if (cfg->conf.privileged_mask > 0) {
      printf("PRIVILEGED_MODE=");
      if (cfg->conf.privileged_mask == PRIV_FULL) {
        printf("full");
      } else {
        bool first = true;
        if (cfg->conf.privileged_mask & PRIV_NOMASK) {
          printf("%snomask", first ? "" : ",");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_NOCAPS) {
          printf("%snocaps", first ? "" : ",");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_NOSEC) {
          printf("%snoseccomp", first ? "" : ",");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_SHARED) {
          printf("%sshared", first ? "" : ",");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_UNFILT) {
          printf("%sunfiltered-dev", first ? "" : ",");
          first = false;
        }
      }
      printf("\n");
    }
  } else {
    /* Human-readable output */
    const char *arch = get_architecture();
    printf("Host: %s\n", arch);

    printf("\nContainer: %s (RUNNING)\n",
           cfg->conf.container_name);
    printf("  PID: %d\n", pid);

    char pretty[256];
    char osr_path[PATH_MAX];
    if (build_proc_root_path(pid, OS_RELEASE, osr_path,
                             sizeof(osr_path)) == 0) {
      get_os_pretty(osr_path, pretty, sizeof(pretty));
      if (pretty[0])
        printf("  OS: %s\n", pretty);
    }

    /* Uptime (only if called from info command) */
    if (!trust_cfg_pid) {
      const long uptime_sec = get_container_uptime(pid);
      if (uptime_sec >= 0) {
        char uptime_str[128];
        format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));
        printf("  Uptime: %s\n", uptime_str);
      }
    }

    printf("\nFeatures:\n");
    int feat_count = 0;

    /* 1. Isolation Network */
    if (cfg->conf.isolation_network) {
      printf("  Isolation network: enabled\n");
      feat_count++;
    }

    /* 2. HW/GPU Access */
    if (cfg->conf.hw_access) {
      printf("  HW access: full\n");
      feat_count++;
    } else if (cfg->conf.gpu_mode) {
      printf("  HW access: GPU\n");
      feat_count++;
    }

    /* 3. Volatile Mode */
    if (cfg->conf.volatile_mode) {
      printf("  Volatile mode: enabled\n");
      feat_count++;
    }

    /* 4. Cgroup v1 */
    if (cfg->conf.force_cgroupv1) {
      printf("  Force Cgroup V1: yes\n");
      feat_count++;
    }

    /* 5. Deadlock Shield (block_nested_ns) */
    if (cfg->conf.block_nested_ns) {
      printf("  Deadlock Shield: enabled\n");
      feat_count++;
    }

    /* 6. Privileged Mode */
    if (cfg->conf.privileged_mask > 0) {
      printf("  Privileged mode: ");
      if (cfg->conf.privileged_mask == PRIV_FULL) {
        printf("full");
      } else {
        bool first = true;
        if (cfg->conf.privileged_mask & PRIV_NOMASK) {
          printf("%snomask", first ? "" : ", ");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_NOCAPS) {
          printf("%snocaps", first ? "" : ", ");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_NOSEC) {
          printf("%snoseccomp", first ? "" : ", ");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_SHARED) {
          printf("%sshared", first ? "" : ", ");
          first = false;
        }
        if (cfg->conf.privileged_mask & PRIV_UNFILT) {
          printf("%sunfiltered-dev", first ? "" : ", ");
          first = false;
        }
      }
      printf("\n");
      feat_count++;
    }

    if (feat_count == 0) {
      printf("  None\n");
    }
  }

  /* Resource limits & live usage. Only show if Cgroup V2 is active,
   * since we skip resource management entirely on V1. We also skip this
   * when called during the boot sequence (!trust_cfg_pid). */
  if (!trust_cfg_pid &&
      (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit) &&
      !cfg->conf.force_cgroupv1 && cgroup_host_is_v2()) {
    long long mu = -1, cu = -1, pu = -1;
    cgroup_get_usage(cfg, &mu, &cu, &pu);
    printf("\nResources:\n");

    if (cfg->conf.memory_limit) {
      char used[32] = "?", lim[32];
      if (mu >= 0)
        format_size(mu, used, sizeof(used));
      format_size(cfg->conf.memory_limit, lim, sizeof(lim));
      printf("  Memory : %s / %s\n", used, lim);
    }
    if (cfg->conf.cpu_quota) {
      const long long period = cfg->conf.cpu_period > 0 ? cfg->conf.cpu_period : 100000;
      const double cores = (double)cfg->conf.cpu_quota / period;
      printf("  CPU    : %.2f cores", cores);
      if (cu >= 0) {
        const long uptime = get_container_uptime(pid);
        if (uptime > 0) {
          /* Average usage as percentage of total capacity (all allocated
           * cores). cu is in usec, uptime in sec. */
          const double usage_sec = (double)cu / 1e6;
          const double avg_util = usage_sec / (double)uptime / cores * 100.0;
          printf(" (Avg usage: %.1f%%)", avg_util);
        } else {
          printf(" (used: %.3fs)", (double)cu / 1e6);
        }
      }
      printf("\n");
    }
    if (cfg->conf.pids_limit) {
      printf("  PIDs   : limit %lld", cfg->conf.pids_limit);
      if (pu >= 0)
        printf(" (current: %lld)", pu);
      printf("\n");
    }
  }

  printf("\n");
  return 0;
}

static int restart_rootfs_with_timeout(cfg_t *cfg, const int timeout_seconds) {
  pid_t pid = 0;
  if (!is_container_running(cfg, &pid) || pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->conf.container_name);
    return -1;
  }
  log_info("Restarting container %s...", cfg->conf.container_name);
  if (stop_rootfs_with_timeout(cfg, true, timeout_seconds) < 0) {
    return -1;
  }
  putchar('\n');
  return start_rootfs(cfg);
}

int restart_rootfs(cfg_t *cfg) {
  return restart_rootfs_with_timeout(cfg, STOP_TIMEOUT);
}
