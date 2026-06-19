/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ds-fork.h"

/* ---------------------------------------------------------------------------
 * External Command Lock - CLI-only ownership
 *
 * The lock represents exactly ONE thing: an external CLI command is actively
 * managing this container. ONLY the CLI parent creates/removes locks.
 * The monitor is READ-ONLY for locks.
 * ---------------------------------------------------------------------------*/

/* Build lock path with defensive truncation.
 * Precision: 2048 (pids_dir) + 256 (name) + 5 (.lock) = 2309 < PATH_MAX (4096)
 * This prevents format-truncation warnings while ensuring paths never overflow.
 */
static int get_lock_path(const char *name, char *buf, size_t size) {
  if (!name || !buf || size == 0 || !validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));
  int r =
      snprintf(buf, size, "%.2048s/%.256s" EXT_LOCK, get_lock_dir(), safe_name);
  return (r > 0 && (size_t)r < size) ? 0 : -1;
}

/* Create external command lock - ONLY called by CLI parent.
 * Uses O_CREAT|O_EXCL for atomic lock acquisition: if two processes race,
 * exactly one gets the lock (the kernel guarantees EEXIST for the loser).
 * Returns: 0 on success, -1 if lock already held by a live process. */
static int acquire_external_lock(const char *name) {
  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return -1;

  /* Try atomic create-and-own.  O_EXCL guarantees mutual exclusion. */
  int fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
  if (fd >= 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    ssize_t w = write_all(fd, pid_str, strlen(pid_str));
    close(fd);
    return (w >= 0) ? 0 : -1;
  }

  if (errno != EEXIST)
    return -1;

  /* Lock file exists — check if holder is still alive. */
  char buf[32];
  if (read_file(lock_path, buf, sizeof(buf)) > 0) {
    pid_t holder = (pid_t)atoi(buf);
    if (holder > 0 && holder != getpid() && kill(holder, 0) == 0) {
      log_warn("Cannot acquire lock: held by process %d", holder);
      return -1;
    }
    /* Stale lock — remove it and retry. */
    if (holder > 0 && holder != getpid())
      log_info("Removing stale lock (holder PID %d is dead)", holder);
  }

  unlink(lock_path);
  /* Retry: another process might beat us, but that's fine — O_EXCL
   * ensures only one of us succeeds. */
  fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
  if (fd >= 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    ssize_t w = write_all(fd, pid_str, strlen(pid_str));
    close(fd);
    return (w >= 0) ? 0 : -1;
  }

  return -1;
}

/* Release external command lock - ONLY called by CLI parent.
 * Verifies ownership before removing. */
static void release_external_lock(const char *name) {
  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return;

  /* Verify we own the lock before removing */
  char buf[32];
  if (read_file(lock_path, buf, sizeof(buf)) > 0) {
    pid_t holder = (pid_t)atoi(buf);
    if (holder == getpid()) {
      unlink(lock_path);
    } else if (holder > 0) {
      /* This should never happen but log it for debugging */
      log_warn("Attempted to release lock owned by PID %d (we are %d)", holder,
               getpid());
    }
  }
}

/* ---------------------------------------------------------------------------
 * Configuration & Metadata Recovery
 * ---------------------------------------------------------------------------*/

/* Check if external command lock exists - called by monitor (READ ONLY).
 * Returns: 1 if lock exists and holder is alive, 0 otherwise. */
int is_external_lock_active(const char *name) {
  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return 0;

  if (access(lock_path, F_OK) != 0)
    return 0; /* No lock */

  /* Lock exists - verify holder is alive */
  char buf[32];
  if (read_file(lock_path, buf, sizeof(buf)) > 0) {
    pid_t holder = (pid_t)atoi(buf);
    if (holder > 0 && kill(holder, 0) == 0)
      return 1; /* Valid lock */

    /* Stale lock detected */
    write_monitor_debug_log(name, "Removing stale lock (holder PID %d is dead)",
                            holder);
  }

  /* Remove stale lock */
  unlink(lock_path);
  return 0;
}

/* ---------------------------------------------------------------------------
 * Cleanup
 * ---------------------------------------------------------------------------*/

void cleanup_container_resources(struct config *cfg,
                                 int skip_unmount, int force_cleanup) {
  /* Flush filesystem buffers (skip if force cleanup - sync can hang on
   * zombie-held fs) */
  if (!force_cleanup)
    sync();

  /* 1. Cleanup firmware path (hw_access mode only; skip on force-cleanup
   * since accessing a zombie-held mount can hang).
   * Use cfg->img_mount_point directly - it is already fully resolved and valid. */
  if (!force_cleanup && cfg->hw_access && cfg->img_mount_point[0]) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 2. Handle Volatile Overlay Cleanup (upper/work/merged)
   * This MUST happen before unmounting the lower image mount.
   * When force_cleanup, use detach+force unmount to avoid hangs. */
  if (cfg->volatile_mode) {
    if (force_cleanup) {
      /* Force path: skip sync, just detach everything */
      char merged[PATH_MAX + 32];
      snprintf(merged, sizeof(merged), "%s/merged", cfg->volatile_dir);
      umount2(merged, MNT_DETACH | MNT_FORCE);
      umount2(cfg->volatile_dir, MNT_DETACH | MNT_FORCE);
      /* Best-effort directory removal */
      remove_recursive(cfg->volatile_dir);
      cfg->volatile_dir[0] = '\0';
    } else {
      cleanup_volatile_overlay(cfg);
    }
  }

  /* 4. Handle rootfs image unmount */
  char mount_point[PATH_MAX] = "";
  if (cfg->img_mount_point[0]) {
    safe_strncpy(mount_point, cfg->img_mount_point, sizeof(mount_point));
  }

  if (mount_point[0] && !skip_unmount) {
    if (force_cleanup) {
      /* Force path: detach+force unmount, no sync, no retry loops */
      umount2(mount_point, MNT_DETACH | MNT_FORCE);
      rmdir(mount_point); /* best-effort */
    } else {
      /* Explicitly call unmount wrapper. It handles its own logging. */
      unmount_rootfs_img(mount_point, cfg->foreground);
    }
  }

  /* 5. Remove tracking info.
   * For restart (skip_unmount), preserve locks so start can detect handoff. */
  if (!skip_unmount) {
    /* Stale lock cleanup is handled by acquire_external_lock and
     * is_external_lock_active. Monitor only does resource cleanup
     * if no external lock is active. */
  }

  /* Network cleanup: remove host-side resources */

  /* Cgroup subtree cleanup: remove /sys/fs/cgroup/ds-fork/<name>/.
   * All container processes are dead by now so every leaf is empty and
   * the bottom-up rmdir walk always succeeds.  Skipped on restart
   * (skip_unmount=1) so the monitor's cgroup context stays intact for
   * the next boot cycle. */
  if (!skip_unmount) {
    cgroup_cleanup_container(cfg->container_name);
  }
}

/* ---------------------------------------------------------------------------
 * Introspection
 * ---------------------------------------------------------------------------*/

int is_valid_container_pid(pid_t pid) {
  char path[PATH_MAX];

  /* Primary marker: /run/ds-fork must exist inside the container.
   * This is the one authoritative marker written by ds-fork on boot.
   * We do NOT require /run/systemd/container - Alpine/runit/openrc never
   * write that file, causing scan to be blind to non-systemd distros. */
  if (build_proc_root_path(pid, FORK_MARKER, path, sizeof(path)) < 0)
    return 0;
  if (access(path, F_OK) != 0)
    return 0;

  /* Secondary check: process must be the init (PID 1) of its namespace.
   * This is more robust than checking cmdline for "init" which distros
   * like Void Linux (runit) or Alpine may not provide. */
  if (!is_container_init(pid))
    return 0;

  return 1;
}

/* ---------------------------------------------------------------------------
 * Start
 * ---------------------------------------------------------------------------*/

int start_rootfs(struct config *cfg) {
  int has_side_effects = 0;
  int lock_acquired = 0;

  /* 0. Early restart detection: check for external lock from previous stop
   *    command to detect a preserved mount for reuse. */
  if (cfg->container_name[0]) {
    char lock_path[PATH_MAX];
    if (get_lock_path(cfg->container_name, lock_path, sizeof(lock_path)) == 0 &&
        access(lock_path, F_OK) == 0) {
      /* This looks like a restart handoff - take ownership of the lock */
      if (acquire_external_lock(cfg->container_name) == 0) {
        lock_acquired = 1;

        /* Try to reuse existing mount from config */
        if (cfg->img_mount_point[0] && is_mountpoint(cfg->img_mount_point)) {
        } else {
          /* Mount not active - remove invalid lock */
          release_external_lock(cfg->container_name);
          lock_acquired = 0;
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
                cfg->container_name, existing_pid);
      goto cleanup;
    }
  }

  /* 2. Preparation */
  ensure_runtime();

  /* 0a. Resolve any symlinks in rootfs image path to canonical absolute paths.
   *     This prevents symlink-based attacks and ensures that all subsequent
   *     operations use the intended location. */
  if (cfg->rootfs_img_path[0]) {
    char *abs_path = resolve_path_arg(cfg->rootfs_img_path);
    if (!abs_path || access(abs_path, F_OK) != 0) {
      log_error("Failed to resolve rootfs image path '%s': %s",
                abs_path ? abs_path : cfg->rootfs_img_path, strerror(errno));
      free(abs_path);
      goto cleanup;
    }
    safe_strncpy(cfg->rootfs_img_path, abs_path, sizeof(cfg->rootfs_img_path));
    free(abs_path);
  }

  /* if foreground was requested but we have no interactive terminal (piped,
   * scripted, config foreground=1, etc.), flip the switch once here and warn
   * once. Covers both CLI and daemon paths. */
  if (cfg->foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->foreground = 0;
    log_warn("No interactive terminal - foreground mode disabled, running in "
             "background.");
  }

  print_cgroup_status(cfg);

  if (cfg->android_storage && !is_android())
    log_warn("--enable-android-storage is only supported on Android hosts. "
             "Skipping.");

  has_side_effects = 1;

  /* 2. Mount rootfs image (using the resolved name) */
  if (cfg->rootfs_img_path[0] && !lock_acquired) {
    if (mount_rootfs_img(cfg->rootfs_img_path, cfg->img_mount_point,
                         sizeof(cfg->img_mount_point), cfg->container_name) < 0) {
      goto cleanup;
    }
  }

  /* 2a. Verify init binary exists before any side effects (NAT, config save).
   * The image is now mounted at img_mount_point. */
  {
    char init_path[PATH_MAX * 2];
    char rootfs_norm[PATH_MAX];
    if (cfg->img_mount_point[0])
      safe_strncpy(rootfs_norm, cfg->img_mount_point, sizeof(rootfs_norm));
    else {
      log_error("Rootfs image mount point not available.");
      return -1;
    }
    size_t rlen = strlen(rootfs_norm);
    if (rlen > 0 && rootfs_norm[rlen - 1] == '/')
      rootfs_norm[rlen - 1] = '\0';

    const char *init_bin =
        cfg->custom_init[0] ? cfg->custom_init : DEFAULT_INIT;
    snprintf(init_path, sizeof(init_path), "%.*s%s",
             (int)(sizeof(init_path) - strlen(init_bin) - 1), rootfs_norm,
             init_bin);
    struct stat st;
    if (lstat(init_path, &st) != 0) {
      log_error("Init binary not found: %s", init_path);
      log_error("Please ensure the rootfs path is correct and contains %s.",
                init_bin);
      unmount_rootfs_img(cfg->img_mount_point, cfg->foreground);
      return -1;
    }
    /* Absolute symlinks resolve correctly inside the container after
     * pivot_root, so skip the X_OK check for symlinks. */
    if (!S_ISLNK(st.st_mode) && access(init_path, X_OK) != 0) {
      log_error("Init binary is not executable: %s", init_path);
      log_error("Ensure it has executable permissions.");
      unmount_rootfs_img(cfg->img_mount_point, cfg->foreground);
      return -1;
    }
  }

  /* 3. Early pre-flight for volatile mode (before any host changes) */
  if (check_volatile_mode(cfg) < 0) {
    goto cleanup;
  }

  {
    char active_uuids[MAX_CONTAINERS][UUID_LEN + 1];
    int uuid_count = collect_active_uuids(active_uuids, MAX_CONTAINERS);
    int need_new = (cfg->uuid[0] == '\0');
    if (!need_new) {
      for (int _i = 0; _i < uuid_count; _i++) {
        if (strcmp(cfg->uuid, active_uuids[_i]) == 0) {
          need_new = 1;
          break;
        }
      }
    }
    if (need_new)
      generate_uuid(cfg->uuid, sizeof(cfg->uuid));
  }

  /* Persist UUID to config immediately
   * so disk always matches the running container. CLI overrides (e.g. -f)
   * are already in cfg at this point since start_rootfs() is called after
   * argument parsing. */
  if (cfg->config_file[0]) {
    int was_new = !cfg->config_file_existed;
    if (config_save(cfg->config_file, cfg) < 0) {
      log_error("Failed to persist configuration to '%s': %s", cfg->config_file,
                strerror(errno));
      goto cleanup;
    }
    if (was_new) {
      log_info("Configuration persisted to " C_BOLD "%s" C_RESET,
               cfg->config_file);
    }
  }

  /* Mirror to workspace so 'start -n <n>' works later without --conf */
  if (config_save_by_name(cfg->container_name, cfg) < 0) {
    log_warn("Failed to mirror configuration to workspace for '%s': %s",
             cfg->container_name, strerror(errno));
  }

  /* Pre-populate volatile_dir for monitor cleanup (actual overlay setup
   * happens inside internal_boot's isolated mount namespace) */
  if (cfg->volatile_mode) {
    snprintf(cfg->volatile_dir, sizeof(cfg->volatile_dir),
             "%s/" RUNTIME_VOLATILE_SUBDIR "/%s", get_runtime_dir(),
             cfg->container_name);
  }

  /* 4. Parent-side PTY allocation (LXC Model) */

  /* Firmware path - hw_access mode only.
   * The image is mounted at img_mount_point.  firmware_path_add() internally
   * checks that /lib/firmware exists in the rootfs before touching the sysfs
   * node. */
  if (cfg->hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->img_mount_point);
    firmware_path_add(fw_path);
  }

  fix_host_ptys();

  if (terminal_create(&cfg->console) < 0) {
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
      ioctl(cfg->console.master, TIOCSWINSZ, &ws);
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
  clock_gettime(CLOCK_BOOTTIME, &cfg->start_time);

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
  if (read(sync_pipe[0], &cfg->container_pid, sizeof(pid_t)) != sizeof(pid_t)) {
    log_error("Monitor failed to send container PID.");
    if (lock_acquired)
      release_external_lock(cfg->container_name);
    goto cleanup;
  }
  close(sync_pipe[0]);
  sync_pipe[0] = -1;

  log_info("Container started with PID %d (Monitor: %d)", cfg->container_pid,
           monitor_pid);

  /* Log volatile mode */
  if (cfg->volatile_mode)
    log_info("Entering volatile mode (OverlayFS)...");

  /* 9. Done - container is running, metadata is in /proc/<pid>/environ */
  if (cfg->img_mount_point[0]) {
    /* Ensure mount point is persisted in config for restart recovery */
    struct config save_cfg = *cfg;
    config_save_by_name(cfg->container_name, &save_cfg);
  }

  /* 10. Foreground or background finish */
  if (cfg->foreground) {

    if (lock_acquired) {
      release_external_lock(cfg->container_name);
      lock_acquired = 0;
    }

    int ret = console_monitor_loop(cfg->console.master, monitor_pid, cfg);
    return ret;
  } else {
    /* Wait for container to finish pivot_root before showing info.
     * The boot sequence writes /run/ds-fork after pivot_root,
     * so we poll for it via /proc/<pid>/root/run/ds-fork. */
    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "/proc/%d/root/run/" PROJECT_NAME,
             cfg->container_pid);
    int booted = 0;
    for (int i = 0; i < 50; i++) { /* 5 seconds max */
      if (access(marker, F_OK) == 0) {
        booted = 1;
        break;
      }
      /* If the container PID is already dead, stop polling */
      if (kill(cfg->container_pid, 0) < 0 && errno == ESRCH)
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

    show_info(cfg, 1);
    log_info("Container '%s' is running in background.", cfg->container_name);
  }

  if (lock_acquired)
    release_external_lock(cfg->container_name);
  config_free(cfg);

  return 0;

cleanup:
  /* Centralized host-side cleanup IF we are returning error.
   * This ensures image mounts and tracking files are reverted on fatal boot
   * errors. Only execute if we successfully crossed the point of creating
   * effects. */
  if (has_side_effects) {
    cleanup_container_resources(cfg, 0, 1 /* force */);
  }
  if (lock_acquired)
    release_external_lock(cfg->container_name);

  if (cfg->console.master >= 0) {
    close(cfg->console.master);
    cfg->console.master = -1;
  }
  if (sync_pipe[0] >= 0)
    close(sync_pipe[0]);
  if (sync_pipe[1] >= 0)
    close(sync_pipe[1]);

  config_free(cfg);
  return -1;
}

int stop_rootfs_with_timeout(struct config *cfg, int skip_unmount,
                             int timeout_seconds) {
  if (timeout_seconds < 0)
    timeout_seconds = STOP_TIMEOUT;

  /* Acquire external command lock FIRST */
  if (acquire_external_lock(cfg->container_name) != 0) {
    log_error("Cannot stop '%s': another command is managing this container",
              cfg->container_name);
    log_error("Wait for the other operation to complete, or use '" PROJECT_NAME
              " "
              "show' to check status");
    return -1;
  }

  pid_t pid = 0;
  if (!is_container_running(cfg, &pid) || pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->container_name);
    release_external_lock(cfg->container_name);
    return -1;
  }

  log_info("Stopping container '%s' (PID %d)...", cfg->container_name, pid);

  /* Safe Metadata Capture: Read mount path from /proc/<pid>/environ
   * before shutdown to preserve it for cleanup if container dies. */
  if (cfg->img_mount_point[0] == '\0') {
    read_proc_environ(pid, "RUNTIME_MOUNT_PATH", cfg->img_mount_point,
                      sizeof(cfg->img_mount_point));
  }

  /* 1. Send shutdown signal. */
  kill(pid, SIGRTMIN + 3); /* SIGRTMIN+3 */

  log_info(
      "Waiting for graceful shutdown (this may take up to %d seconds)...",
      timeout_seconds);

  /* 2. Wait for exit */
  int stopped = 0;
  for (int i = 0; i < timeout_seconds * 5; i++) {
    if (kill(pid, 0) < 0) {
      if (errno == ESRCH) {
        stopped = 1;
        break;
      }
    }
    usleep(RETRY_DELAY_US);
  }

  /* 3. Force kill if still running */
  int unkillable = 0;
  if (!stopped) {
    log_warn("Graceful stop timed out, sending SIGKILL...");
    kill(pid, SIGKILL);

    /*
     * Wait up to 5 seconds for the kernel to clean up the process.
     * We don't use blocking waitpid() because we aren't the parent,
     * and we want a timeout to prevent hanging on unkillable PIDs.
     */
    int killed = 0;
    for (int j = 0; j < 25; j++) { /* 5 seconds total */
      if (kill(pid, 0) < 0 && errno == ESRCH) {
        killed = 1;
        break;
      }
      usleep(200000); /* 200ms */
    }

    if (!killed) {
      unkillable = 1;
      log_error("Container PID %d is in an unkillable state!", pid);
      log_warn("This often happens on old Android kernels due to zombie "
               "processes.\nPlease restart your device to clear it.");
      log_warn("Proceeding with best-effort host cleanup (no sync)...");
    }
  }

  /* 4. Firmware cleanup (hw_access mode only).
   * Skip when unkillable - accessing zombie-held rootfs can hang. */
  if (cfg->img_mount_point[0] && !unkillable && cfg->hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 5. Complete resource cleanup. */
  cleanup_container_resources(cfg, skip_unmount, unkillable);

  if (!cfg->foreground)
    log_info("Container '%s' stopped.", cfg->container_name);

  /* Release lock ONLY if this is a final stop.
   * For restarts (skip_unmount=1), keep lock alive as handoff. */
  if (!skip_unmount) {
    release_external_lock(cfg->container_name);
  }

  return 0;
}

int stop_rootfs(struct config *cfg, int skip_unmount) {
  return stop_rootfs_with_timeout(cfg, skip_unmount, STOP_TIMEOUT);
}

/* ---------------------------------------------------------------------------
 * Other operations
 * ---------------------------------------------------------------------------*/

static const char *get_architecture(void) {
  static struct utsname uts;
  if (uname(&uts) != 0)
    return "unknown";
  return uts.machine;
}

static void parse_pretty_name(FILE *fp, char *buf, size_t size) {
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

static void get_os_pretty(const char *osrelease_path, char *buf, size_t size) {
  if (!buf || size == 0)
    return;
  buf[0] = '\0';

  FILE *fp = fopen(osrelease_path, "r");
  if (!fp)
    return;

  parse_pretty_name(fp, buf, size);
  fclose(fp);
}

int show_info(struct config *cfg, int trust_cfg_pid) {
  /* Case 1: No container name specified - try auto-resolution or listing */
  if (cfg->container_name[0] == '\0') {
    char first_name[256];
    int count = count_running_containers(first_name, sizeof(first_name));

    if (count == 0) {
      const char *host = is_android() ? "Android" : "Linux";
      const char *arch = get_architecture();
      printf(C_GREEN "Host:" C_RESET " %s %s\n", host, arch);
      printf("\n" C_YELLOW "Container:" C_RESET " No containers running.\n\n");
      return 0;
    }

    if (count == 1) {
      /* Auto-resolve to the only running container */
      safe_strncpy(cfg->container_name, first_name,
                   sizeof(cfg->container_name));
    } else {
      /* Multiple containers running, show Host info and list */
      const char *host = is_android() ? "Android" : "Linux";
      const char *arch = get_architecture();
      printf(C_GREEN "Host:" C_RESET " %s %s\n", host, arch);
      printf("\n" C_YELLOW "Multiple containers running:" C_RESET "\n");
      show_containers(cfg);
      printf("\nUse '" C_GREEN "--name <NAME> info" C_RESET
             "' for detailed information.\n\n");
      return 0;
    }
  }

  /* Now we have a container name. Ensure its config is loaded from the source
   * of truth (container.config) so we show accurate feature info without
   * expensive live probing. */
  if (!trust_cfg_pid) {
    config_load_by_name(cfg->container_name, cfg);
  }

  /* Case 2: Validate running status */
  pid_t pid = 0;
  if (trust_cfg_pid && cfg->container_pid > 0) {
    /* Trust the PID we just got from the sync pipe.
     * We assume it's running because parent waited for boot marker. */
    pid = cfg->container_pid;
  } else {
    /* For other calls (e.g., info command), read and validate from pidfile. */
    is_container_running(cfg, &pid);
  }

  if (pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->container_name);
    return -1;
  }

  /* Success - print Host and detailed Container info */
  if (cfg->format_output) {
    const char *host = is_android() ? "Android" : "Linux";
    const char *arch = get_architecture();
    printf("HOST_PLATFORM=%s\n", host);
    printf("HOST_ARCH=%s\n", arch);
    printf("CONTAINER_NAME=%s\n", cfg->container_name);
    printf("CONTAINER_PID=%d\n", pid);

    char pretty[256];
    char osr_path[PATH_MAX];
    if (build_proc_root_path(pid, "/etc/os-release", osr_path,
                             sizeof(osr_path)) == 0) {
      get_os_pretty(osr_path, pretty, sizeof(pretty));
      if (pretty[0])
        printf("CONTAINER_OS=%s\n", pretty);
    }

    if (!trust_cfg_pid) {
      long uptime_sec = get_container_uptime(pid);
      if (uptime_sec >= 0) {
        char uptime_str[128];
        format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));
        printf("CONTAINER_UPTIME=%s\n", uptime_str);
        printf("CONTAINER_UPTIME_SEC=%ld\n", uptime_sec);
      }
    }

    const char *net;
    switch (cfg->net_mode) {
    case NET_NONE:
      net = "none";
      break;
    default:
      net = "host";
      break;
    }
    printf("NETWORKING_MODE=%s\n", net);

    if (is_android())
      printf("ANDROID_STORAGE=%d\n", cfg->android_storage);

    if (cfg->hw_access)
      printf("HW_ACCESS=full\n");
    else if (cfg->gpu_mode)
      printf("HW_ACCESS=GPU\n");
    else
      printf("HW_ACCESS=none\n");

    printf("VOLATILE_MODE=%d\n", cfg->volatile_mode);
    printf("FORCE_CGROUP_V1=%d\n", cfg->force_cgroupv1);
    printf("DEADLOCK_SHIELD=%d\n", cfg->block_nested_ns);
    printf("FOREGROUND_MODE=%d\n", cfg->foreground);

    if (cfg->privileged_mask > 0) {
      printf("PRIVILEGED_MODE=");
      if (cfg->privileged_mask == PRIV_FULL) {
        printf("full");
      } else {
        int first = 1;
        if (cfg->privileged_mask & PRIV_NOMASK) {
          printf("%snomask", first ? "" : ",");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_NOCAPS) {
          printf("%snocaps", first ? "" : ",");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_NOSEC) {
          printf("%snoseccomp", first ? "" : ",");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_SHARED) {
          printf("%sshared", first ? "" : ",");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_UNFILTERED) {
          printf("%sunfiltered-dev", first ? "" : ",");
          first = 0;
        }
      }
      printf("\n");
    }

    printf("BIND_MOUNT_COUNT=%d\n", cfg->bind_count);
    show_container_usage(cfg);
  } else {
    /* Human-readable output */
    const char *host = is_android() ? "Android" : "Linux";
    const char *arch = get_architecture();
    printf(C_GREEN "Host:" C_RESET " %s %s\n", host, arch);

    printf("\n" C_GREEN "Container:" C_RESET " %s (RUNNING)\n",
           cfg->container_name);
    printf("  PID: %d\n", pid);

    char pretty[256];
    char osr_path[PATH_MAX];
    if (build_proc_root_path(pid, "/etc/os-release", osr_path,
                             sizeof(osr_path)) == 0) {
      get_os_pretty(osr_path, pretty, sizeof(pretty));
      if (pretty[0])
        printf("  OS: %s\n", pretty);
    }

    /* Uptime (only if called from info command) */
    if (!trust_cfg_pid) {
      long uptime_sec = get_container_uptime(pid);
      if (uptime_sec >= 0) {
        char uptime_str[128];
        format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));
        printf("  Uptime: %s\n", uptime_str);
      }
    }

    printf("\n" C_GREEN "Features:" C_RESET "\n");
    int feat_count = 0;

    /* 1. Networking Mode */
    const char *net;
    switch (cfg->net_mode) {
    case NET_NONE:
      net = "none";
      break;
    default:
      net = "host";
      break;
    }
    printf("  Networking: %s\n", net);
    feat_count++;

    /* 2. Android Storage */
    if (is_android() && cfg->android_storage) {
      printf("  Android storage: enabled\n");
      feat_count++;
    }

    /* 3. HW/GPU Access */
    if (cfg->hw_access) {
      printf("  " C_RED "HW access:" C_RESET " full\n");
      feat_count++;
    } else if (cfg->gpu_mode) {
      printf("  HW access: GPU\n");
      feat_count++;
    }

    /* 5. Volatile Mode */
    if (cfg->volatile_mode) {
      printf("  Volatile mode: enabled\n");
      feat_count++;
    }

    /* 6. Cgroup v1 */
    if (cfg->force_cgroupv1) {
      printf("  " C_RED "Force Cgroup V1:" C_RESET " yes\n");
      feat_count++;
    }

    /* 7. Deadlock Shield (block_nested_ns) */
    if (cfg->block_nested_ns) {
      printf("  " C_RED "Deadlock Shield:" C_RESET " enabled\n");
      feat_count++;
    }

    /* 8. Privileged Mode */
    if (cfg->privileged_mask > 0) {
      printf("  " C_RED "Privileged mode:" C_RESET " ");
      if (cfg->privileged_mask == PRIV_FULL) {
        printf("full");
      } else {
        int first = 1;
        if (cfg->privileged_mask & PRIV_NOMASK) {
          printf("%snomask", first ? "" : ", ");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_NOCAPS) {
          printf("%snocaps", first ? "" : ", ");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_NOSEC) {
          printf("%snoseccomp", first ? "" : ", ");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_SHARED) {
          printf("%sshared", first ? "" : ", ");
          first = 0;
        }
        if (cfg->privileged_mask & PRIV_UNFILTERED) {
          printf("%sunfiltered-dev", first ? "" : ", ");
          first = 0;
        }
      }
      printf("\n");
      feat_count++;
    }

    /* 9. Bind Mounts */
    if (cfg->bind_count > 0) {
      printf("  Bind mounts: %d active\n", cfg->bind_count);
      feat_count++;
    }

    /* 10. Custom Init */
    if (cfg->custom_init[0]) {
      printf("  " C_RED "Custom Init:" C_RESET " %s\n", cfg->custom_init);
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
      (cfg->memory_limit || cfg->cpu_quota || cfg->pids_limit) &&
      !cfg->force_cgroupv1 && cgroup_host_is_v2()) {
    long long mu = -1, cu = -1, pu = -1;
    cgroup_get_usage(cfg, &mu, &cu, &pu);
    printf("\n" C_GREEN "Resources:" C_RESET "\n");

    if (cfg->memory_limit) {
      char used[32] = "?", lim[32];
      if (mu >= 0)
        format_size(mu, used, sizeof(used));
      format_size(cfg->memory_limit, lim, sizeof(lim));
      printf("  Memory : %s / %s\n", used, lim);
    }
    if (cfg->cpu_quota) {
      long long period = cfg->cpu_period > 0 ? cfg->cpu_period : 100000;
      double cores = (double)cfg->cpu_quota / period;
      printf("  CPU    : %.2f cores", cores);
      if (cu >= 0) {
        long uptime = get_container_uptime(pid);
        if (uptime > 0) {
          /* Average usage as percentage of total capacity (all allocated
           * cores). cu is in usec, uptime in sec. */
          double usage_sec = (double)cu / 1e6;
          double avg_util = (usage_sec / (double)uptime) / cores * 100.0;
          printf(" (Avg usage: %.1f%%)", avg_util);
        } else {
          printf(" (used: %.3fs)", (double)cu / 1e6);
        }
      }
      printf("\n");
    }
    if (cfg->pids_limit) {
      printf("  PIDs   : limit %lld", cfg->pids_limit);
      if (pu >= 0)
        printf(" (current: %lld)", pu);
      printf("\n");
    }
  }

  printf("\n");
  return 0;
}

int restart_rootfs_with_timeout(struct config *cfg, int timeout_seconds) {
  pid_t pid = 0;
  if (!is_container_running(cfg, &pid) || pid <= 0) {
    log_error("Container '%s' is not running or invalid.", cfg->container_name);
    return -1;
  }
  log_info("Restarting container %s...", cfg->container_name);
  if (stop_rootfs_with_timeout(cfg, 1, timeout_seconds) < 0) {
    return -1;
  }
  putchar('\n');
  return start_rootfs(cfg);
}

int restart_rootfs(struct config *cfg) {
  return restart_rootfs_with_timeout(cfg, STOP_TIMEOUT);
}
