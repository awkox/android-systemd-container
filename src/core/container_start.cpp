#include "asc.h"

static int active_lock_fd = -1;
static fs::path active_lock_path = "";

int acquire_external_lock(std::string_view name) {
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

bool is_external_lock_active(std::string_view name) {
  fs::path lock_path = lock_dir / name;

  auto_close const int fd = open(lock_path.c_str(), O_RDONLY | O_CLOEXEC);
  return !(fd < 0);
}

void cleanup_container_resources(const asc_rt_t *rt, const bool force_cleanup) {
  if (!force_cleanup)
    sync();

  cgroup_cleanup_container(rt->container_name);

  fs::path mount_point = mount_dir / rt->container_name;
  if (is_mountpoint(mount_point)) {
    if (force_cleanup) {
      umount2(mount_point.c_str(), MNT_DETACH | MNT_FORCE);
      fs::remove(mount_point);
    } else {
      unmount_rootfs_img(mount_point, rt->foreground);
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

  fs::path lock_path = lock_dir / cfg->rt.container_name;
  if (fs::exists(lock_path)) {
    if (acquire_external_lock(cfg->rt.container_name) == 0) {
      lock_acquired = true;

      if (is_mountpoint(mount_dir / cfg->rt.container_name)) {
        cleanup_container_resources(&cfg->rt, false);
      } else {
        release_external_lock();
        lock_acquired = false;
      }
    }
  }

  if (!lock_acquired) {
    if (is_container_running(cfg->rt.container_name, &existing_pid)) {
      log_error("容器名称 '%s' 已被 PID %d 占用。",
                cfg->rt.container_name.c_str(), existing_pid);
      goto cleanup;
    }
  }

  if (!cfg->conf.rootfs_img_path.empty()) {
    fs::path abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (abs_path.empty() || !fs::exists(abs_path)) {
      log_error("无法解析 rootfs 镜像路径 '%s': %s",
                abs_path.empty() ? cfg->conf.rootfs_img_path.c_str() : abs_path.c_str(), strerror(errno));
      goto cleanup;
    }
  }

  if (cfg->rt.foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->rt.foreground = 0;
    log_warn("无交互式终端 - 已禁用前台模式，转入后台运行。");
  }

  has_side_effects = true;

  if (!cfg->rt.config_file.empty()) {
    bool was_new = !cfg->rt.config_file_existed;
    if (config_save(cfg->rt.config_file, cfg) < 0) {
      log_error("无法持久化配置到 '%s': %s", cfg->rt.config_file.c_str(), strerror(errno));
      goto cleanup;
    }
    if (was_new) {
      log_info("配置已成功持久化至 %s", cfg->rt.config_file.c_str());
    }
  }

  if (config_save_by_name(cfg->rt.container_name, cfg) < 0) {
    log_warn("无法将工作区镜像配置同步至 '%s': %s",
             cfg->rt.container_name.c_str(), strerror(errno));
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

  if (lock_acquired) release_external_lock();

  if (cfg->rt.foreground) {
    return console_monitor_loop(cfg->rt.console.master, monitor_pid, cfg);
  } else {
    // 直接返回，monitor 负责后续一切
    log_info("容器 '%s' 已提交至后台 (PID %d, Monitor %d)。",
             cfg->rt.container_name.c_str(), cfg->rt.container_pid, monitor_pid);
    return 0;
  }

cleanup:
  if (has_side_effects) {
    cleanup_container_resources(&cfg->rt, true);
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