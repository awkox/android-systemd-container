#include "asc.h"

struct InitArgs {
  cfg_t *cfg;
  int sync_fd;
};

static int init_trampoline(void *arg) {
  InitArgs *args = static_cast<InitArgs *>(arg);
  
  /* 阻塞等待父进程(Monitor)将我们安全迁入 Cgroup 树 */
  char c;
  if (read(args->sync_fd, &c, 1) < 0) {}
  close(args->sync_fd);

  /* 现在我们在正确的 Cgroup 中，执行 Cgroup 命名空间隔离锁定 */
  if (unshare(CLONE_NEWCGROUP) < 0) {
    log_error("Init Cgroup 隔离失败: %s", strerror(errno));
    return -1;
  }

  internal_boot(args->cfg);
  return -1; 
}

/* ---------------------------------------------------------------------------
 * monitor_run - 容器的监督守护进程
 *
 * 在 start_rootfs() 的 fork() 之后立即被调用。此函数永远不会返回，最终
 * 会调用 _exit() 退出。sync_pipe_write 用于首次引导时向父进程发送 init PID。
 * ---------------------------------------------------------------------------*/
void monitor_run(cfg_t *cfg, int sync_pipe_write) {
  int sync_pipe[2] = {-1, sync_pipe_write};
  bool stdio_redirected = false;

  if (setsid() < 0 && errno != EPERM) {
    log_error("Monitor setsid 失败: %s", strerror(errno));
    _exit(EXIT_FAILURE);
  }

  /* 监控器安全加固
   * 忽略常见的终止信号，防止 Android 进程管理器意外终止监督器。
   * Monitor 只能通过 SIGKILL 或容器正常退出来销毁。 */
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);

  /* 保护监控器及后续创建的所有容器进程不被 OOM Killer 杀掉 */
  oom_protect();

  prctl(PR_SET_NAME, "[ds-monitor]", 0, 0, 0);

  fs::path cg_path = project_cgroup_dir / cfg->rt.container_name;
  create_directories_with_permission(cg_path);

  /* 支持自动重启的引导循环机制 */
  int status = 0;
  bool should_reboot = false;
  bool is_reboot_request = false;

  do {
    /* 后台模式的标准输入输出重定向 */
    if (!cfg->rt.foreground && !stdio_redirected) {
      int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 0);
        close(devnull);
      }
      stdio_redirected = true;
    }

    const size_t stack_size = 2 * 1024 * 1024;
    void *stack = malloc(stack_size);
    if (!stack) _exit(EXIT_FAILURE);
    void *stack_top = static_cast<char *>(stack) + stack_size;

    int pipefd[2];
    if (pipe(pipefd) < 0) _exit(EXIT_FAILURE);
    InitArgs args = {cfg, pipefd[0]};

    int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
    if (cfg->conf.isolation_network) clone_flags |= CLONE_NEWNET;

    /* 直接克隆 Init 进程，消除冗余的 Intermediate 节点 */
    pid_t init_pid = clone(init_trampoline, stack_top, clone_flags, &args);
    close(pipefd[0]);

    if (init_pid < 0) {
      log_error("clone 容器进程失败: %s", strerror(errno));
      free(stack);
      close(pipefd[1]);
      _exit(EXIT_FAILURE);
    }
      write_file(cg_path / "cgroup.procs", std::format("{}\n", init_pid));

      /* 释放 Init 进程，允许它推进引导过程 */
      char wake_char = 'A';
      if (write(pipefd[1], &wake_char, 1) < 0) {}
      close(pipefd[1]);
      if (sync_pipe[1] >= 0) {
        if (write(sync_pipe[1], &init_pid, sizeof(pid_t)) != sizeof(pid_t)) {
        }
        close(sync_pipe[1]);
        sync_pipe[1] = -1;
      }

    cfg->rt.container_pid = init_pid;
    cfg->rt.ns_inode = get_pid_ns_inode(cfg->rt.container_pid);

    if (chdir("/") < 0) {
      log_warn("无法 chdir 到 /: %s", strerror(errno));
    }

    /* 利用 pidfd (无轮询事件驱动) 高效等待容器退出 */
    {
      int pfd = syscall(SYS_pidfd_open, init_pid, 0);
      if (pfd < 0) {
        log_error("pidfd_open失败：%s", strerror(errno));
        free(stack);
        _exit(EXIT_FAILURE);
      }

      sigset_t mask;
      sigemptyset(&mask);
      sigaddset(&mask, SIGCHLD);
      sigprocmask(SIG_BLOCK, &mask, nullptr);
      int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

      struct pollfd pfds[2] = {};
      pfds[0].fd = pfd; pfds[0].events = POLLIN;
      pfds[1].fd = sfd; pfds[1].events = POLLIN;
      int nfds = (sfd >= 0) ? 2 : 1;
      bool reaped = false;

      while (1) {
        int r = poll(pfds, nfds, -1);
        if (r < 0 && errno == EINTR) continue;

        if (pfds[0].revents & POLLIN) {
          break;
        }

        if (nfds == 2 && (pfds[1].revents & POLLIN)) {
          struct signalfd_siginfo si;
          while (read(sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si)))
            ;
          pid_t rpid = waitpid(init_pid, &status, WNOHANG);
          if (rpid == init_pid) {
            reaped = true;
            break;
          }
        }
      }
      close(sfd);
      close(pfd);
      sigprocmask(SIG_UNBLOCK, &mask, nullptr);
      if (!reaped) waitpid(init_pid, &status, 0);
    }
    free(stack);
    
    /* 记录监控器捕获的退出状态与重启信号判定 */
    is_reboot_request = false;

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
        /* Systemd 约定：容器内使用 SIGHUP 触发宿主重启 */
        is_reboot_request = true;
        log_info("[MONITOR] 检测到容器内部发起了重启请求 (SIGHUP)");
      } else if (sig == SIGINT || sig == (SIGRTMIN + 3) || sig == (SIGRTMIN + 4) || sig == (SIGRTMIN + 13) || sig == (SIGRTMIN + 14)) {
        /* Systemd 约定：这些信号均代表不同层次的 Halt / Poweroff 请求 */
        log_info("[MONITOR] 检测到容器内部发起了关机请求 (Signal %d)", sig);
      } else {
        log_warn("[MONITOR] Init 进程被信号异常终止: %d (%s)", sig, strsignal(sig));
      }
    }

    /* 重启检测：若为重启请求且无外部锁竞争，则准备下一轮引导 */
    should_reboot = false;
    if (is_reboot_request) {
      if (is_external_lock_active(cfg->rt.container_name)) {
        log_warn("[MONITOR] 检测到外部命令锁 - 中止内部重启，移交控制权给 CLI");
      } else {
        if (cfg->rt.foreground) {
          printf("\n容器 %s 正在重启\r\n", cfg->rt.container_name.c_str());
          fflush(stdout);
        }

        cfg->rt.reboot_cycle = true;
        clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

        /* 重置容器 PID 以让 Monitor 后续的 while 循环能够正确探测新生容器 */
        cfg->rt.container_pid = 0;
        cfg->rt.ns_inode = 0;
        if (cfg->rt.foreground)

        should_reboot = true;
      }
    }
  } while (should_reboot);

  /* 非重启路径：检查外部锁是否已介入 */
  if (!is_reboot_request) {
    if (is_external_lock_active(cfg->rt.container_name)) {
      log_info("[MONITOR] 检测到外部命令锁 - 将资源清理交由 CLI 完成");
      _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
    }
  }

  /* 正常退出清理 */
  log_info("[MONITOR] 正在执行退出清理工作");
  cleanup_container_resources(cfg->rt.container_name, false);

  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}