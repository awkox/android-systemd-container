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
      write_all(fd, pid_str.c_str(), pid_str.size());
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

  // 只需要清理全局可见的 Cgroup，挂载点和 Loop 设备内核会自动回收
  cgroup_cleanup_container(rt->container_name);
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
  int sync_pipe[2] = {-1, -1};
  pid_t monitor_pid = -1;
  pid_t existing_pid = -1;

  log_info("正在获取容器独占锁与资源...");
  if (acquire_external_lock(cfg->rt.container_name) == 0) {
    lock_acquired = true;
    // 发现僵尸锁，直接清理上一轮可能残留的全局资源 (Cgroup)
    cleanup_container_resources(&cfg->rt, false);
  }

  if (!lock_acquired) {
    if (is_container_running(cfg->rt.container_name, &existing_pid)) {
      log_error("容器名称 '%s' 已被 PID %d 占用。",
                cfg->rt.container_name.c_str(), existing_pid);
      goto cleanup;
    }
  }

  if (!cfg->conf.rootfs_img_path.empty()) {
    log_info("校验并解析 Rootfs 路径配置...");
    fs::path abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (abs_path.empty() || !fs::exists(abs_path)) {
      log_error("无法解析 rootfs 镜像路径 '%s': %s",
                abs_path.empty() ? cfg->conf.rootfs_img_path.c_str() : abs_path.c_str(), strerror(errno));
      goto cleanup;
    }
  }

  if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
    cfg->rt.foreground = false;
    log_warn("无交互式终端 - 自动转入后台运行。");
  }

  has_side_effects = true;

  if (!cfg->rt.config_file.empty()) {
    if (config_save(cfg->rt.config_file, cfg) < 0) {
      log_error("无法持久化配置到 '%s': %s", cfg->rt.config_file.c_str(), strerror(errno));
      goto cleanup;
    }
  }

  if (config_save_by_name(cfg->rt.container_name, cfg) < 0) {
    log_warn("无法将工作区镜像配置同步至 '%s': %s",
             cfg->rt.container_name.c_str(), strerror(errno));
  }

  log_info("正在分配并设置容器虚拟控制台 (PTY Console)...");
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

  log_info("正在孵化 Monitor 监控守护进程...");
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

  if (lock_acquired)
    release_external_lock();

  if (cfg->rt.foreground) {
    return console_monitor_loop(cfg->rt.console.master, monitor_pid, cfg);
  } else {
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
