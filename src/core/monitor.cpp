#include "asc.h"

struct InitArgs {
  cfg_t &cfg;
  int sync_fd;          // pipefd[0]: 当前 Init 用来接收唤醒信号的读端
  int wake_write_fd;    // pipefd[1]: 属于 Monitor 的唤醒写端（应关闭）
  int sync_pipe_write;  // sync_fd: 属于 Monitor 向 CLI 通信的写端（应关闭）
};

static int init_trampoline(void *arg) {
  InitArgs *args = static_cast<InitArgs *>(arg);
  
  // 1. 修复 FD 泄漏：显式关闭继承自父进程但属于父进程的管道写端
  if (args->wake_write_fd >= 0) close(args->wake_write_fd);
  if (args->sync_pipe_write >= 0) close(args->sync_pipe_write);

  /* 2. 阻塞等待父进程(Monitor)将我们安全迁入 Cgroup 树 */
  char c;
  if (read(args->sync_fd, &c, 1) < 0) {
    // 顺手修复：安全隐患（读失败不应静默忽略，否则会引发竞争条件）
    log_error("Init 进程读取同步信号失败: %s", strerror(errno));
    return -1;
  }
  close(args->sync_fd);

  /* 现在我们在正确的 Cgroup 中，执行 Cgroup 命名空间隔离锁定 */
  if (unshare(CLONE_NEWCGROUP) < 0) {
    log_error("Init Cgroup 隔离失败: %s", strerror(errno));
    return -1;
  }

  internal_boot(args->cfg);
  return -1; 
}

// 子模块 1: 环境与上下文初始化
static void setup_monitor_environment(cfg_t &cfg) {
  if (setsid() < 0 && errno != EPERM) {
    log_error("Monitor setsid 失败: %s", strerror(errno));
    _exit(EXIT_FAILURE);
  }

  /* 忽略终止信号，防止管理器意外终止，保护 OOM */
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  
  oom_protect();
  prctl(PR_SET_NAME, "[ds-monitor]", 0, 0, 0);

  fs::path cg_path = project_cgroup_dir / cfg.rt.container_name;
  create_directories_with_permission(cg_path);
}

// 子模块 2: 后台模式 IO 重定向
static void redirect_stdio_to_null() {
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    terminal_set_stdfds(devnull);
    close(devnull);
  }
}

// 子模块 3: 孵化与唤醒容器 Init 进程
static pid_t launch_container_init(cfg_t &cfg, void *stack_top, int *sync_fd) {
  int pipefd[2];
  if (pipe2(pipefd, O_CLOEXEC) < 0) {
    return -1;
  }

  InitArgs args = {cfg, pipefd[0], pipefd[1], *sync_fd};
  int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
  if (cfg.conf.isolation_network) clone_flags |= CLONE_NEWNET;

  pid_t init_pid = clone(init_trampoline, stack_top, clone_flags, &args);
  close(pipefd[0]); // 父进程关闭供子进程读取的管道端

  if (init_pid < 0) {
    log_error("clone 容器进程失败: %s", strerror(errno));
    close(pipefd[1]);
    return -1;
  }

  /* 将子进程迁入 Cgroup */
  fs::path cg_path = project_cgroup_dir / cfg.rt.container_name;
  write_file(cg_path / "cgroup.procs", std::format("{}\n", init_pid));

  /* 释放 Init 进程，允许其推进引导 */
  char wake_char = 'A';
  if (write(pipefd[1], &wake_char, 1) < 0) {}
  close(pipefd[1]);

  /* 首次启动时通知 CLI 工具 */
  if (*sync_fd >= 0) {
    if (write(*sync_fd, &init_pid, sizeof(pid_t)) != sizeof(pid_t)) {}
    close(*sync_fd);
    *sync_fd = -1; // 标记为已消费
  }

  return init_pid;
}

// 子模块 4: 高效阻塞等待容器退出
static int wait_for_container_exit(pid_t init_pid) {
  int status = 0;
  int pfd = syscall(SYS_pidfd_open, init_pid, 0);
  if (pfd < 0) {
    log_error("pidfd_open失败：%s", strerror(errno));
    return -1;
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

  pollfd pfds[2] = {};
  pfds[0].fd = pfd; pfds[0].events = POLLIN;
  pfds[1].fd = sfd; pfds[1].events = POLLIN;
  int nfds = (sfd >= 0) ? 2 : 1;
  bool reaped = false;

  while (true) {
    int r = poll(pfds, nfds, -1);
    if (r < 0 && errno == EINTR) continue;

    if (pfds[0].revents & POLLIN) {
      break;
    }

    if (nfds == 2 && (pfds[1].revents & POLLIN)) {
      signalfd_siginfo si;
      while (read(sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si)))
        ;
      pid_t rpid = waitpid(init_pid, &status, WNOHANG);
      if (rpid == init_pid) {
        reaped = true;
        break;
      }
    }
  }

  if (sfd >= 0) close(sfd);
  close(pfd);
  sigprocmask(SIG_UNBLOCK, &mask, nullptr);
  
  if (!reaped) waitpid(init_pid, &status, 0);
  
  return status;
}

// 子模块 5: 退出状态分析与重启决策
static bool evaluate_reboot_request(int status, cfg_t &cfg) {
  bool is_reboot_request = false;

  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == REBOOT_EXIT) {
      is_reboot_request = true;
      log_info("[MONITOR] 检测到容器内部发起了重启请求 (退出码: %d)", code);
    } else {
      log_info("[MONITOR] 检测到容器正常关机 (退出码: %d)", code);
    }
  } else if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    if (sig == SIGHUP) {
      is_reboot_request = true;
      log_info("[MONITOR] 检测到容器内部发起了重启请求 (SIGHUP)");
    } else if (sig == SIGINT || sig == (SIGRTMIN + 3) ||
               sig == (SIGRTMIN + 4) || sig == (SIGRTMIN + 13) ||
               sig == (SIGRTMIN + 14)) {
      log_info("[MONITOR] 检测到容器内部发起了关机请求 (Signal %d)", sig);
    } else {
      log_warn("[MONITOR] Init 进程被信号异常终止: %d (%s)", sig, strsignal(sig));
    }
  }

  if (is_reboot_request) {
    if (is_external_lock_active(cfg.rt.container_name)) {
      log_warn("[MONITOR] 检测到外部命令锁 - 中止内部重启，移交控制权给 CLI");
      return false;
    } 
    
    if (cfg.rt.foreground) {
      log_info("容器 %s 正在重启", cfg.rt.container_name.c_str());
      fflush(stdout);
    }
    cfg.rt.reboot_cycle = true;
    clock_gettime(CLOCK_BOOTTIME, &cfg.rt.start_time);

    // 重置运行时 PID 标识以进入下一轮
    cfg.rt.container_pid = 0;
    cfg.rt.ns_inode = 0;
    return true;
  }
  
  return false;
}

// 主函数: monitor_run 监督主循环
void monitor_run(cfg_t &cfg, int sync_pipe_write) {
  setup_monitor_environment(cfg);

  int sync_fd = sync_pipe_write;
  bool stdio_redirected = false;
  int status = 0;
  bool should_reboot = false;

  constexpr size_t stack_size = 2 * 1024 * 1024;

  do {
    if (!cfg.rt.foreground && !stdio_redirected) {
      redirect_stdio_to_null();
      stdio_redirected = true;
    }

    void *stack = malloc(stack_size);
    if (!stack) _exit(EXIT_FAILURE);
    void *stack_top = static_cast<char *>(stack) + stack_size;

    // 1. 孵化 Init 进程
    pid_t init_pid = launch_container_init(cfg, stack_top, &sync_fd);
    if (init_pid < 0) {
      free(stack);
      _exit(EXIT_FAILURE);
    }

    cfg.rt.container_pid = init_pid;
    cfg.rt.ns_inode = get_pid_ns_inode(init_pid);
    log_info("容器启动成功，主 PID 为 %d (Monitor PID: %d)", init_pid, getpid());

    if (chdir("/") < 0) {
      log_warn("无法 chdir 到 /: %s", strerror(errno));
    }

    // 2. 挂起 Monitor 自身，阻塞监听容器退出
    status = wait_for_container_exit(init_pid);
    
    // 3. 显式释放栈内存
    free(stack);

    if (status < 0) {
      _exit(EXIT_FAILURE);
    }

    // 4. 判断是否需要自旋重启
    should_reboot = evaluate_reboot_request(status, cfg);

  } while (should_reboot);

  log_info("[MONITOR] 容器主进程已退出，Monitor 正在执行退出清理工作...");
  cleanup_container_resources(cfg.rt.container_name, false);

  log_info("[MONITOR] 资源清理完毕，守护进程退出。");
  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}