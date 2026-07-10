#include "asc.h"

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

  /* 自适应 Cgroup 命名空间支持 */
  bool allow_cgroup_ns = fs::exists("/proc/self/ns/cgroup");
  if (allow_cgroup_ns) {
    if (fs::exists("/sys/fs/cgroup/cgroup.procs")) {
      if (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit) {
        char enable[64] = "";
        int eoff = 0;
        if (auto content = read_file_cpp("/sys/fs/cgroup/cgroup.controllers")) {
          const struct {
            long long limit;
            const char *controller;
          } ctrl_map[] = {
            {cfg->conf.memory_limit, "memory"},
            {cfg->conf.cpu_quota,    "cpu"},
            {cfg->conf.pids_limit,   "pids"},
          };
          for (const auto &c : ctrl_map) {
            if (c.limit && cg_word_in_list(content->c_str(), c.controller)) {
              const int n = snprintf(enable + eoff,
                                     sizeof(enable) - static_cast<size_t>(eoff),
                                     "%s+%s", eoff ? " " : "", c.controller);
              if (n > 0)
                eoff += n;
            }
          }
        }
        if (eoff > 0) {
          if (write_file("/sys/fs/cgroup/cgroup.subtree_control", enable) < 0)
            log_warn("[CGROUP] subtree_control (root): %s", strerror(errno));
          create_directories_with_permission("/sys/fs/cgroup/asc");
          if (write_file("/sys/fs/cgroup/asc/cgroup.subtree_control", enable) < 0)
            log_warn("[CGROUP] subtree_control (asc): %s", strerror(errno));
        }
      }

      fs::path cg_path = project_cgroup_dir / cfg->rt.container_name;
      create_directories_with_permission(cg_path);
    }
  }

  /* 应用资源限制 */
  if (cgroup_apply_limits(cfg) < 0 &&
      (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit))
    log_warn("[CGROUP] 部分资源限制未能成功应用。");

  /* 支持自动重启的引导循环机制 */
reboot_loop:;

  /* 后台模式的标准输入输出重定向 */
  if (!cfg->rt.foreground && !stdio_redirected) {
    auto_close int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
    }
  }

  pid_t mid_pid = fork();
  if (mid_pid < 0)
    _exit(EXIT_FAILURE);

  if (mid_pid == 0) {
    /* ==== 中间进程 (Intermediate Process) ====
     * 负责为本次引导周期创建全新的命名空间 */
     
    if (allow_cgroup_ns) {
      fs::path cg_procs = project_cgroup_dir / cfg->rt.container_name / "cgroup.procs";
      FILE *f = fopen(cg_procs.c_str(), "we");
      if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
      }
    }

    int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC;
    if (cfg->conf.isolation_network)
      clone_flags |= CLONE_NEWNET;
    if (allow_cgroup_ns)
      clone_flags |= CLONE_NEWCGROUP;

    if (unshare(clone_flags) < 0) {
      log_error("命名空间隔离(unshare)失败: %s", strerror(errno));
      _exit(EXIT_FAILURE);
    }

    pid_t init_pid = fork();
    if (init_pid < 0)
      _exit(EXIT_FAILURE);

    if (init_pid == 0) {
      /* 容器内的 INIT 进程 (PID 1) */
      close(sync_pipe[1]);
      sync_pipe[1] = -1;
      internal_boot(cfg);
      _exit(-1); 
    }

    if (!cfg->rt.foreground) {
      auto_close int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
      }
    }

    /* 首次引导时将 init PID 发送给父进程 */
    if (sync_pipe[1] >= 0) {
      if (write(sync_pipe[1], &init_pid, sizeof(pid_t)) != sizeof(pid_t)) {
      }
      close(sync_pipe[1]);
      sync_pipe[1] = -1;
    }

    int init_status;
    while (waitpid(init_pid, &init_status, 0) < 0 && errno == EINTR)
      ;

    if (WIFSIGNALED(init_status) && WTERMSIG(init_status) == SIGHUP) {
      _exit(REBOOT_EXIT);
    }

    _exit(WIFEXITED(init_status) ? WEXITSTATUS(init_status) : EXIT_FAILURE);
  }

  /* ==== 监控进程 (Monitor) ==== */

  if (sync_pipe[1] >= 0) {
    close(sync_pipe[1]);
    sync_pipe[1] = -1;
  }

  cfg->rt.ns_inode = get_pid_ns_inode(cfg->rt.container_pid);

  if (chdir("/") < 0) {
    log_warn("无法 chdir 到 /: %s", strerror(errno));
  }

  if (!cfg->rt.foreground && !stdio_redirected) {
    auto_close int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
    }
    stdio_redirected = true;
  }

  /* 监控器心跳循环：每 500ms 刷新一次虚拟化数据，并探测子进程 */
  int status = 0;
  {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, nullptr);
    auto_close int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    while (1) {
      pid_t r = waitpid(mid_pid, &status, WNOHANG);
      if (r == mid_pid)
        break;
      if (r < 0 && errno != EINTR)
        break;

      if (cfg->rt.container_pid <= 0 && cfg->conf.uuid[0] != '\0') {
        pid_t p = find_container_init_pid(cfg->rt.container_name, cfg->conf.uuid);
        if (p > 0) {
          cfg->rt.container_pid = p;
          cfg->rt.ns_inode = get_pid_ns_inode(p);
          write_monitor_debug_log(cfg->rt.container_name,
                                  "[VIRT] 已通过 /proc 扫描解析到 container_pid=%d "
                                  "ns_inode=%lu",
                                  (int)p, cfg->rt.ns_inode);
        }
      }

      virtualize_update(cfg);

      if (sfd >= 0) {
        struct pollfd pfd = {.fd = sfd, .events = POLLIN, .revents = 0};
        poll(&pfd, 1, 500);
        if (pfd.revents & POLLIN) {
          struct signalfd_siginfo si;
          while (read(sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si)))
            ;
        }
      } else {
        usleep(500000);
      }
    }

    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
  }

  /* 记录监控器捕获的退出状态 */
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == REBOOT_EXIT) {
      write_monitor_debug_log(cfg->rt.container_name, "检测到容器内部发起了重启请求");
    } else {
      write_monitor_debug_log(cfg->rt.container_name,
                              "检测到容器正常关机 (退出码: %d)", code);
    }
  } else if (WIFSIGNALED(status)) {
    write_monitor_debug_log(cfg->rt.container_name,
                            "中间进程被信号异常终止: %d (%s)",
                            WTERMSIG(status), strsignal(WTERMSIG(status)));
  }

  /* 重启检测 */
  if (WIFEXITED(status) && WEXITSTATUS(status) == REBOOT_EXIT) {
    if (is_external_lock_active(cfg->rt.container_name)) {
      write_monitor_debug_log(
          cfg->rt.container_name,
          "检测到外部命令锁 - 中止内部重启，移交控制权给 CLI");
      goto monitor_cleanup_and_exit;
    }

    if (cfg->rt.foreground) {
      printf("\n容器 %s 正在重启\n", cfg->rt.container_name);
      fflush(stdout);
    }

    /* 将 .boot-uuid 写入真实的挂载点内，而非旧容器失效的 proc 路径 */
    if (!cfg->conf.volatile_mode && cfg->conf.img_mount_point[0]) {
      fs::path run_dir = fs::path(cfg->conf.img_mount_point) / "run";
      mkdir(run_dir.c_str(), 0755);
      fs::path uuid_path = run_dir / ".boot-uuid";
      auto_close int fd = open(uuid_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        size_t ulen = strlen(cfg->conf.uuid);
        write_all(fd, cfg->conf.uuid, ulen);
      }
    }

    /* 重新加载工作区配置 */
    {
      cfg_t reboot_cfg = *cfg;
      if (config_load_by_name(cfg->rt.container_name, &reboot_cfg) == 0) {
        *cfg = reboot_cfg;
      }
    }

    cfg->rt.reboot_cycle = true;
    clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

    /* 重置容器 PID 以让 Monitor 后续的 while 循环能够正确探测新生容器 */
    cfg->rt.container_pid = 0;
    cfg->rt.ns_inode = 0;
    if (cfg->rt.foreground)
      log_silent = 1;

    goto reboot_loop;
  }

  if (is_external_lock_active(cfg->rt.container_name)) {
    write_monitor_debug_log(cfg->rt.container_name,
                            "检测到外部命令锁 - 将资源清理交由 CLI 完成");
    goto monitor_cleanup_and_exit;
  }

  /* 正常退出清理 */
  write_monitor_debug_log(cfg->rt.container_name, "监控器正在执行退出清理工作");

  cleanup_container_resources(cfg, false);

monitor_cleanup_and_exit:
  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}