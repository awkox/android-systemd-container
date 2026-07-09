#include "asc.h"

static int active_lock_fd = -1;
static char active_lock_path[PATH_MAX] = "";

std::string get_lock_path(std::string_view name) {
  return std::format("{}/{}.lock", get_lock_dir(), name);
}

int acquire_external_lock(const char *name) {
  if (active_lock_fd >= 0)
    return 0;

  std::string lock_path = get_lock_path(name);
  if (lock_path.size() >= PATH_MAX) return -1;

  const int fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  struct flock fl = {};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;

  if (fcntl(fd, F_SETLK, &fl) == 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(fd, 0) == 0) {
      write_all(fd, pid_str, strlen(pid_str));
    }

    active_lock_fd = fd;
    safe_strncpy(active_lock_path, lock_path.c_str(), sizeof(active_lock_path));
    return 0;
  }

  if (errno == EACCES || errno == EAGAIN) {
    fl.l_type = F_WRLCK;
    if (fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK) {
      log_warn("无法获取锁: 当前已被进程 %d 持有", fl.l_pid);
    }
  }

  close(fd);
  return -1;
}

void release_external_lock(void) {
  if (active_lock_fd >= 0) {
    if (active_lock_path[0]) {
      unlink(active_lock_path);
    }

    close(active_lock_fd);
    active_lock_fd = -1;
    active_lock_path[0] = '\0';
  }
}

bool is_external_lock_active(const char *name) {
  std::string lock_path = get_lock_path(name);
  if (lock_path.size() >= PATH_MAX) return false;

  auto_close const int fd = open(lock_path.c_str(), O_RDONLY | O_CLOEXEC);
  return !(fd < 0);
}

void cleanup_container_resources(cfg_t *cfg, const bool force_cleanup) {
  if (!force_cleanup)
    sync();

  if (cfg->conf.volatile_mode) {
    if (force_cleanup) {
      char merged[PATH_MAX + 32];
      snprintf(merged, sizeof(merged), "%s/merged", cfg->rt.volatile_dir);
      umount2(merged, MNT_DETACH | MNT_FORCE);
      umount2(cfg->rt.volatile_dir, MNT_DETACH | MNT_FORCE);
      remove_recursive(cfg->rt.volatile_dir);
      cfg->rt.volatile_dir[0] = '\0';
    } else {
      cleanup_volatile_overlay(&cfg->rt);
    }
  }

  char mount_point[PATH_MAX] = "";
  if (cfg->conf.img_mount_point[0]) {
    safe_strncpy(mount_point, cfg->conf.img_mount_point, sizeof(mount_point));
  }

  if (mount_point[0]) {
    if (force_cleanup) {
      umount2(mount_point, MNT_DETACH | MNT_FORCE);
      rmdir(mount_point);
    } else {
      unmount_rootfs_img(mount_point, cfg->rt.foreground);
    }
  }

  cgroup_cleanup_container(cfg->rt.container_name);
}

bool is_valid_container_pid(const pid_t pid) {
  char path[PATH_MAX];

  if (build_proc_root_path(pid, FORK_MARKER, path, sizeof(path)) < 0)
    return false;
  if (!fs::exists(path))
    return false;

  if (!is_container_init(pid))
    return false;

  return true;
}

int start_rootfs(cfg_t *cfg) {
  bool has_side_effects = false;
  bool lock_acquired = false;
  pid_t existing_pid = 0;
  int sync_pipe[2] = {-1, -1};
  pid_t monitor_pid = -1;
  char marker[PATH_MAX];
  bool booted = false;

  if (cfg->rt.container_name[0]) {
    std::string lock_path = get_lock_path(cfg->rt.container_name);
    if (lock_path.size() < PATH_MAX && fs::exists(lock_path)) {
      if (acquire_external_lock(cfg->rt.container_name) == 0) {
        lock_acquired = true;

        if (cfg->conf.img_mount_point[0] && is_mountpoint(cfg->conf.img_mount_point)) {
        } else {
          release_external_lock();
          lock_acquired = false;
        }
      }
    }
  }

  if (!lock_acquired) {
    if (is_container_running(cfg->conf.uuid, &existing_pid)) {
      log_error("容器名称 '%s' 已被 PID %d 占用。",
                cfg->rt.container_name, existing_pid);
      goto cleanup;
    }
  }

  ensure_runtime();

  if (cfg->conf.rootfs_img_path[0]) {
    std::string abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (abs_path.empty() || !fs::exists(abs_path)) {
      log_error("无法解析 rootfs 镜像路径 '%s': %s",
                abs_path.empty() ? cfg->conf.rootfs_img_path : abs_path.c_str(), strerror(errno));
      goto cleanup;
    }
    safe_strncpy(cfg->conf.rootfs_img_path, abs_path.c_str(), sizeof(cfg->conf.rootfs_img_path));
  }

  if (cfg->rt.foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->rt.foreground = 0;
    log_warn("无交互式终端 - 已禁用前台模式，转入后台运行。");
  }

  print_cgroup_status(cfg);

  has_side_effects = true;

  if (cfg->conf.rootfs_img_path[0] && !lock_acquired) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, cfg->conf.img_mount_point,
                         sizeof(cfg->conf.img_mount_point), cfg->rt.container_name) < 0) {
      goto cleanup;
    }
  }

  {
    char init_path[PATH_MAX * 2];
    char rootfs_norm[PATH_MAX];
    if (cfg->conf.img_mount_point[0])
      safe_strncpy(rootfs_norm, cfg->conf.img_mount_point, sizeof(rootfs_norm));
    else {
      log_error("未获取到 Rootfs 镜像挂载点。");
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
      log_error("未找到 Init 文件: %s", init_path);
      log_error("请确保 rootfs 路径正确且包含了 %s 可执行文件。",
                init_bin);
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
    if (!S_ISLNK(st.st_mode) && access(init_path, X_OK) != 0) {
      log_error("Init 文件没有可执行权限: %s", init_path);
      log_error("请确保为其赋予可执行权限 (chmod +x)。");
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
  }

  if (check_volatile_mode(&cfg->conf) < 0) {
    goto cleanup;
  }

  {
    auto active_uuids = collect_active_uuids();
    bool need_new = (cfg->conf.uuid[0] == '\0');
    if (!need_new) {
      // 借助 std::find 一行完成查找
      if (std::find(active_uuids.begin(), active_uuids.end(), cfg->conf.uuid) != active_uuids.end()) {
        need_new = true;
      }
    }
    if (need_new)
      generate_uuid(cfg->conf.uuid, sizeof(cfg->conf.uuid));
  }

  if (cfg->rt.config_file[0]) {
    bool was_new = !cfg->rt.config_file_existed;
    if (config_save(cfg->rt.config_file, cfg) < 0) {
      log_error("无法持久化配置到 '%s': %s", cfg->rt.config_file,
                strerror(errno));
      goto cleanup;
    }
    if (was_new) {
      log_info("配置已成功持久化至 %s", cfg->rt.config_file);
    }
  }

  if (config_save_by_name(cfg->rt.container_name, cfg) < 0) {
    log_warn("无法将工作区镜像配置同步至 '%s': %s",
             cfg->rt.container_name, strerror(errno));
  }

  if (cfg->conf.volatile_mode) {
    snprintf(cfg->rt.volatile_dir, sizeof(cfg->rt.volatile_dir),
             "%s/" RUNTIME_VOLATILE_SUBDIR "/%s", get_runtime_dir(),
             cfg->rt.container_name);
  }

  fix_host_ptys();

  if (terminal_create(&cfg->rt.console) < 0) {
    log_error("无法分配容器控制台 (Console) PTY");
    goto cleanup;
  }

  if (isatty(STDIN_FILENO)) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(cfg->rt.console.master, TIOCSWINSZ, &ws);
  }

  if (pipe(sync_pipe) < 0) {
    log_error("创建管道失败: %s", strerror(errno));
    goto cleanup;
  }

  fcntl(sync_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl(sync_pipe[1], F_SETFD, FD_CLOEXEC);

  clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

  monitor_pid = fork();
  if (monitor_pid < 0) {
    close(sync_pipe[0]);
    close(sync_pipe[1]);
    log_error("fork(Monitor) 失败: %s", strerror(errno));
    goto cleanup;
  }

  if (monitor_pid == 0) {
    close(sync_pipe[0]);
    monitor_run(cfg, sync_pipe[1]);
    _exit(EXIT_FAILURE);
  }

  close(sync_pipe[1]);

  if (read(sync_pipe[0], &cfg->rt.container_pid, sizeof(pid_t)) != sizeof(pid_t)) {
    log_error("Monitor 监控进程未能发送容器 PID。");
    goto cleanup;
  }
  close(sync_pipe[0]);
  sync_pipe[0] = -1;

  log_info("容器启动成功，主 PID 为 %d (Monitor PID: %d)", cfg->rt.container_pid,
           monitor_pid);

  if (cfg->conf.volatile_mode)
    log_info("正在进入易失模式 (OverlayFS)...");

  if (cfg->conf.img_mount_point[0]) {
    cfg_t save_cfg = *cfg;
    config_save_by_name(cfg->rt.container_name, &save_cfg);
  }

  if (cfg->rt.foreground) {
    if (lock_acquired) {
      release_external_lock();
    }
    int ret = console_monitor_loop(cfg->rt.console.master, monitor_pid, cfg);
    return ret;
  } else {
    snprintf(marker, sizeof(marker), "/proc/%d/root/run/" PROJECT_NAME,
             cfg->rt.container_pid);
    for (int i = 0; i < 50; i++) {
      if (fs::exists(marker)) {
        booted = true;
        break;
      }
      if (kill(cfg->rt.container_pid, 0) < 0 && errno == ESRCH)
        break;
      usleep(100000);
    }

    if (!booted) {
      log_error("容器未能正确完成引导流程。");
      goto cleanup;
    }

    show_info(cfg, true);
    log_info("容器 '%s' 正在后台运行。", cfg->rt.container_name);
  }

  if (lock_acquired)
    release_external_lock();

  return 0;

cleanup:
  if (has_side_effects) {
    cleanup_container_resources(cfg, true);
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
