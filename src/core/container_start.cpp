#include "asc.h"

static int active_lock_fd = -1;
static fs::path active_lock_path = "";

int acquire_external_lock(const char *name) {
  if (active_lock_fd >= 0)
    return 0;

  fs::path lock_path = lock_dir / name;

  const int fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  struct flock fl = {};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;

  if (fcntl(fd, F_SETLK, &fl) == 0) {
    std::string pid_str = std::format("{}\n", getpid());
    if (ftruncate(fd, 0) == 0) {
      write_all(fd, pid_str.c_str(), strlen(pid_str.c_str()));
    }

    active_lock_fd = fd;
    active_lock_path = lock_path;
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
    if (!active_lock_path.empty()) {
      fs::remove(active_lock_path);
    }

    close(active_lock_fd);
    active_lock_fd = -1;
    active_lock_path = "";
  }
}

bool is_external_lock_active(const char *name) {
  fs::path lock_path = lock_dir / name;

  auto_close const int fd = open(lock_path.c_str(), O_RDONLY | O_CLOEXEC);
  return !(fd < 0);
}

void cleanup_container_resources(cfg_t *cfg, const bool force_cleanup) {
  if (!force_cleanup)
    sync();

  cgroup_cleanup_container(cfg->rt.container_name);

  fs::path mount_point = mount_dir / cfg->rt.container_name;
  if (is_mountpoint(mount_point)) {
    if (force_cleanup) {
      umount2(mount_point.c_str(), MNT_DETACH | MNT_FORCE);
      fs::remove(mount_point);
    } else {
      unmount_rootfs_img(mount_point, cfg->rt.foreground);
    }
  }
}

bool is_valid_container_pid(const pid_t pid) {
  fs::path path = proc_dir / std::to_string(pid) / "root";
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
  bool booted = false;

  fs::path lock_path = lock_dir / cfg->rt.container_name;
  if (fs::exists(lock_path)) {
    if (acquire_external_lock(cfg->rt.container_name) == 0) {
      lock_acquired = true;

      if (is_mountpoint(mount_dir / cfg->rt.container_name)) {
        // 跳过移除挂载
        cgroup_cleanup_container(cfg->rt.container_name);
      } else {
        release_external_lock();
        lock_acquired = false;
      }
    }
  }

  if (!lock_acquired) {
    if (is_container_running(cfg->rt.container_name, &existing_pid)) {
      log_error("容器名称 '%s' 已被 PID %d 占用。",
                cfg->rt.container_name, existing_pid);
      goto cleanup;
    }
  }

  if (cfg->conf.rootfs_img_path[0]) {
    fs::path abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (abs_path.empty() || !fs::exists(abs_path)) {
      log_error("无法解析 rootfs 镜像路径 '%s': %s",
                abs_path.empty() ? cfg->conf.rootfs_img_path : abs_path.c_str(), strerror(errno));
      goto cleanup;
    }
  }

  if (cfg->rt.foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->rt.foreground = 0;
    log_warn("无交互式终端 - 已禁用前台模式，转入后台运行。");
  }

  has_side_effects = true;

  if (cfg->conf.rootfs_img_path[0] && !lock_acquired) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, mount_dir / cfg->rt.container_name) < 0) {
      goto cleanup;
    }
  }

  {
    fs::path init_bin = cfg->conf.custom_init[0] ? 
             fs::path(cfg->conf.custom_init) : fs::path(DEFAULT_INIT);
    init_bin = init_bin.relative_path();
    fs::path init_path = mount_dir / cfg->rt.container_name / init_bin;

    struct stat st;
    if (lstat(init_path.c_str(), &st) != 0) {
      log_error("未找到 Init 文件: %s", init_path.c_str());
      log_error("请确保 rootfs 路径正确且包含了 %s 可执行文件。",
                init_bin.c_str());
      goto cleanup;
    }
    if (!S_ISLNK(st.st_mode) && access(init_path.c_str(), X_OK) != 0) {
      log_error("Init 文件没有可执行权限: %s", init_path.c_str());
      log_error("请确保为其赋予可执行权限 (chmod +x)。");
      goto cleanup;
    }
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

  {
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
    // 根据项目设计强制要求 Cgroup V2，此处的探测退化为极速验证
    for (int i = 0; i < 50; i++) {
      if (find_container_init_pid(cfg->rt.container_name) == cfg->rt.container_pid) {
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