#include "asc.h"

/* ---------------------------------------------------------------------------
 * monitor_run - Supervisor process for a single container instance.
 *
 * Called immediately after fork() in start_rootfs(). Never returns - always
 * ends with _exit(). sync_pipe_write is the write-end of the parent sync
 * pipe; the monitor (or its intermediate child) writes the container init PID
 * through it on the first boot cycle, then closes it.
 * ---------------------------------------------------------------------------*/
void monitor_run(cfg_t *cfg, int sync_pipe_write) {
  int sync_pipe[2];
  sync_pipe[0] = -1;
  sync_pipe[1] = sync_pipe_write;

  if (setsid() < 0 && errno != EPERM) {
    /* Fatal only if it's not EPERM (which means already leader) */
    log_error("setsid failed: %s", strerror(errno));
    _exit(EXIT_FAILURE);
  }

  /* Monitor Hardening
   * Ignore common termination signals to prevent Android's process manager
   * from ending the supervisor prematurely. Monitor must only die via
   * SIGKILL or successful container exit. */
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);

  /* Make monitor unkillable */
  oom_protect();

  prctl(PR_SET_NAME, "[ds-monitor]", 0, 0, 0);

  /* Adaptive Cgroup Namespace (introduced in Linux 4.6).
   *
   * CGROUP SELECTION: Only enable cgroupns when V2 is active.
   * If --force-cgroupv1 is set, we skip cgroupns so setup_cgroups()
   * has full rights to create named V1 hierarchies from the host context. */
  bool cg_ns_ok = access("/proc/self/ns/cgroup", F_OK) == 0 &&
                 cgroup_host_is_v2() && !cfg->conf.force_cgroupv1;
  if (cg_ns_ok) {
    /* To get isolation from a cgroup namespace, we must be in a sub-cgroup
     * BEFORE we unshare. If we are in the root '/', the namespace root
     * will be the host's root, providing zero isolation.
     * We use a container-specific path to avoid conflicts. */
    if (access("/sys/fs/cgroup/cgroup.procs", F_OK) == 0) {
      char safe_name[256];
      sanitize_container_name(cfg->conf.container_name, safe_name,
                              sizeof(safe_name));

      /* v2：在 mkdir 之前自上而下启用请求的控制器。遍历两个层级：
       * /sys/fs/cgroup -> /sys/fs/cgroup/asc */
      if (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit) {
        /* Build enable string with snprintf offsets instead of strncat to
         * avoid truncation. Use cg_word_in_list() for exact word-boundary
         * matching to prevent false positives (e.g. matching "cpuset"
         * when looking for "cpu"). */
        char enable[64] = {0};
        char buf[256];
        int eoff = 0;
        if (read_file("/sys/fs/cgroup/cgroup.controllers", buf, sizeof(buf)) >
            0) {
          if (cfg->conf.memory_limit && cg_word_in_list(buf, "memory")) {
            int n = snprintf(enable + eoff, sizeof(enable) - (size_t)eoff,
                             "%s+memory", eoff ? " " : "");
            if (n > 0)
              eoff += n;
          }
          if (cfg->conf.cpu_quota && cg_word_in_list(buf, "cpu")) {
            int n = snprintf(enable + eoff, sizeof(enable) - (size_t)eoff,
                             "%s+cpu", eoff ? " " : "");
            if (n > 0)
              eoff += n;
          }
          if (cfg->conf.pids_limit && cg_word_in_list(buf, "pids")) {
            int n = snprintf(enable + eoff, sizeof(enable) - (size_t)eoff,
                             "%s+pids", eoff ? " " : "");
            if (n > 0)
              eoff += n;
          }
        }
        if (eoff > 0) {
          if (write_file("/sys/fs/cgroup/cgroup.subtree_control", enable) < 0)
            log_warn("[CGROUP] subtree_control (root): %s", strerror(errno));
          mkdir_p("/sys/fs/cgroup/" PROJECT_NAME, 0755);
          if (write_file("/sys/fs/cgroup/" PROJECT_NAME
                         "/cgroup.subtree_control",
                         enable) < 0)
            log_warn("[CGROUP] subtree_control (" PROJECT_NAME "): %s",
                     strerror(errno));
        }
      }

      char cg_path[PATH_MAX];
      snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/" PROJECT_NAME "/%s",
               safe_name);
      mkdir_p(cg_path, 0755);

      char cg_procs[PATH_MAX];
      safe_strncpy(cg_procs, cg_path, sizeof(cg_procs));
      strncat(cg_procs, "/cgroup.procs",
              sizeof(cg_procs) - strlen(cg_procs) - 1);
    }
  } else {
    /* Legacy kernel without force flag - skip cgroupns, run in host
     * cgroupns with full rights so setup_cgroups() can create named
     * v1 hierarchies. */
  }

  /* Apply resource limits. On v2 hosts this writes memory.max / cpu.max /
   * pids.max into the delegated cgroup. On v1 or --force-cgroupv1 the
   * function skips with a warning since v1 delegation is unreliable. */
  if (cgroup_apply_limits(cfg) < 0 &&
      (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit))
    log_warn("[CGROUP] Some resource limits could not be enforced.");

  bool stdio_redirected = false;

  /* Reboot-aware boot loop
   * Each iteration forks an intermediate child that creates a fresh PID
   * namespace (unshare(CLONE_NEWPID)) and then forks the container init.
   *
   * Reboot detection uses EXIT CODES ONLY (no signal interception):
   *   1. Init calls reboot(2) → kernel kills init with SIGHUP
   *   2. Intermediate sees WTERMSIG(init)==SIGHUP via waitpid()
   *   3. Intermediate exits with REBOOT_EXIT (249)
   *   4. Monitor sees WEXITSTATUS(mid)==249 → loop back
   *
   * This eliminates ghost containers because the Monitor never handles
   * SIGHUP - it only checks a deterministic exit code. */
reboot_loop:;

  /* Stdio handling for monitor in background mode (early redirection).
   * We must do this BEFORE forking the intermediate process, otherwise
   * the intermediate inherits the user's stdout/stderr (e.g. a pipe)
   * and holds it open indefinitely, causing CLI hangs in direct mode. */
  if (!cfg->rt.foreground && !stdio_redirected) {
    auto_close int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      /* Note: we don't redirect 1 and 2 here yet because we want to see
       * networking setup logs. We'll do a full redirect after the fork. */
    }
  }

  pid_t mid_pid = fork();
  if (mid_pid < 0)
    _exit(EXIT_FAILURE);

  if (mid_pid == 0) {
    /* INTERMEDIATE PROCESS
     * Create fresh namespaces for this boot cycle. */
     
    /* 中间进程加入容器的 Cgroup */
    if (cg_ns_ok) {
      char safe_name[256];
      sanitize_container_name(cfg->conf.container_name, safe_name, sizeof(safe_name));
      char cg_procs[PATH_MAX];
      snprintf(cg_procs, sizeof(cg_procs), "/sys/fs/cgroup/" PROJECT_NAME "/%s/cgroup.procs", safe_name);
      
      FILE *f = fopen(cg_procs, "we");
      if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
      }
    }

    /* 执行 Namespace 隔离 */
    int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC;
    if (cfg->conf.isolation_network)
      clone_flags |= CLONE_NEWNET;
    if (cg_ns_ok)
      clone_flags |= CLONE_NEWCGROUP;

    if (unshare(clone_flags) < 0) {
      log_error("unshare failed: %s", strerror(errno));
      _exit(EXIT_FAILURE);
    }

    pid_t init_pid = fork();
    if (init_pid < 0)
      _exit(EXIT_FAILURE);

    if (init_pid == 0) {
      /* CONTAINER INIT (PID 1 inside namespace) */
      close(sync_pipe[1]);
      internal_boot(cfg);
      _exit(-1); // fail
    }

    /* Intermediate: 现在（在 fork init 之后）将 stdio 重定向到 /dev/null。
     * 它的存在仅仅是为了等待 init，不需要与用户的终端交互或保持管道打开。
     *
     * 错误修复：这个重定向以前被放在 fork() 之前，这导致 init_pid 继承了 
     * /dev/null 作为 fd 1 和 fd 2。internal_boot() 内部的每次 log_info() 
     * 调用都会被 /dev/null 默默吞噬。将重定向移到这里意味着只有中间进程
     * 本身保持静默；internal_boot() 会保留原始的终端文件描述符，
     * 直到在它自己的第 21 步将其重定向到 /dev/console。*/
    if (!cfg->rt.foreground) {
      auto_close int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
      }
    }

    /* Send init PID to parent via sync pipe (first boot only) */
    if (sync_pipe[1] >= 0) {
      if (write(sync_pipe[1], &init_pid, sizeof(pid_t)) != sizeof(pid_t)) {
        /* Reader will detect failure or handle empty/partial read */
      }
      close(sync_pipe[1]);
      sync_pipe[1] = -1;
    } else {
      /* Reboot cycle - PID will be discovered via /proc scan. */
    }

    /* Wait for init to exit */
    int init_status;
    while (waitpid(init_pid, &init_status, 0) < 0 && errno == EINTR)
      ;

    /* Convert kernel signal to exit code:
     * SIGHUP from reboot(RESTART) → REBOOT_EXIT (249)
     * Everything else → pass through as-is */
    if (WIFSIGNALED(init_status) && WTERMSIG(init_status) == SIGHUP) {
      _exit(REBOOT_EXIT);
    }

    _exit(WIFEXITED(init_status) ? WEXITSTATUS(init_status) : EXIT_FAILURE);
  }

  /* MONITOR continues here */

  /* Close sync pipe write end (intermediate handles it) */
  if (sync_pipe[1] >= 0) {
    close(sync_pipe[1]);
    sync_pipe[1] = -1;
  }

  /* Capture PID namespace inode for virtualization PID-recycling guard.
   * container_pid may be 0 on HOST mode until pidfile is written - that's
   * fine; get_pid_ns_inode(0) returns 0 and update will skip safely. */
  cfg->rt.ns_inode = get_pid_ns_inode(cfg->rt.container_pid);

  /* Ensure monitor is not sitting inside any mount point */
  if (chdir("/") < 0) {
    log_warn("Failed to chdir to /: %s", strerror(errno));
  }

  /* Stdio handling for monitor in background mode (first boot only) */
  if (!cfg->rt.foreground && !stdio_redirected) {
    auto_close int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
    }
    stdio_redirected = true;
  }

  /* MONITOR waits for intermediate to complete */

  /* CRITICAL TIMING: Close sync pipe write end ONLY after intermediate
   * finishes. This ensures intermediate can write init PID to parent on first
   * boot. Closing too early causes parent's read() to return EOF, triggering
   * cleanup that deletes the PID file while container is still booting. See
   * commit 6f9f99a for details on the boot-at-boot race this prevents. */
  if (sync_pipe[1] >= 0) {
    close(sync_pipe[1]);
    sync_pipe[1] = -1;
  }

  /* Monitor heartbeat loop: 500ms poll + virtualization update.
   * WNOHANG lets us update virtual /proc files while waiting for mid_pid. */
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

      /* HOST mode: resolve container_pid via /proc scan using UUID.
       * Poll until we have a valid PID, then capture ns_inode once. */
      if (cfg->rt.container_pid <= 0 && cfg->conf.uuid[0] != '\0') {
        pid_t p = find_container_init_pid(cfg->conf.uuid);
        if (p > 0) {
          cfg->rt.container_pid = p;
          cfg->rt.ns_inode = get_pid_ns_inode(p);
          write_monitor_debug_log(cfg->conf.container_name,
                                  "[VIRT] resolved container_pid=%d "
                                  "ns_inode=%lu from /proc",
                                  (int)p, cfg->rt.ns_inode);
        }
      }

      virtualize_update(cfg);

      if (sfd >= 0) {
        struct pollfd pfd = {.fd = sfd, .events = POLLIN};
        poll(&pfd, 1, 500);
        if (pfd.revents & POLLIN) {
          struct signalfd_siginfo si;
          while (read(sfd, &si, sizeof(si)) == (ssize_t)sizeof(si))
            ; /* drain */
        }
      } else {
        usleep(500000);
      }
    }

    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
  }

  /* Log what monitor saw */
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == REBOOT_EXIT) {
      write_monitor_debug_log(cfg->conf.container_name, "Detected internal REBOOT");
    } else {
      write_monitor_debug_log(cfg->conf.container_name,
                              "Detected container SHUTDOWN (exit: %d)", code);
    }
  } else if (WIFSIGNALED(status)) {
    write_monitor_debug_log(cfg->conf.container_name,
                            "Intermediate killed by signal: %d (%s)",
                            WTERMSIG(status), strsignal(WTERMSIG(status)));
  }

  /* Reboot detection (internal reboot) */
  if (WIFEXITED(status) && WEXITSTATUS(status) == REBOOT_EXIT) {
    /* Check for external lock - if exists, abort reboot and let CLI handle it
     */
    if (is_external_lock_active(cfg->conf.container_name)) {
      write_monitor_debug_log(
          cfg->conf.container_name,
          "External command lock detected - aborting internal reboot");
      goto monitor_cleanup_and_exit;
    }

    if (cfg->rt.foreground) {
      printf("\nContainer %s is now Rebooting\n", cfg->conf.container_name);
      fflush(stdout);
    }

    /* Synchronize container_pid in Monitor via /proc scan */
    if (cfg->conf.uuid[0] != '\0') {
      pid_t new_pid = find_container_init_pid(cfg->conf.uuid);
      if (new_pid > 0)
        cfg->rt.container_pid = new_pid;
    }

    /* Write UUID to container /run (via procfs) so internal_boot can read it
     * across the pivot_root boundary without touching user's rootfs. */
    if (!cfg->conf.volatile_mode && cfg->rt.container_pid > 0) {
      char run_dir[PATH_MAX];
      snprintf(run_dir, sizeof(run_dir), "/proc/%d/root/run",
               cfg->rt.container_pid);
      mkdir(run_dir, 0755);
      auto_close int fd = safe_openat_proc(cfg->rt.container_pid, "run/.boot-uuid",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        size_t ulen = strlen(cfg->conf.uuid);
        write_all(fd, cfg->conf.uuid, ulen);
      }
    }

    /* Reload from workspace (canonical path the user edits) */
    {
      bool old_force_cgv1 = cfg->conf.force_cgroupv1;

      cfg_t reboot_cfg = *cfg;
      if (config_load_by_name(cfg->conf.container_name, &reboot_cfg) == 0) {
        /* Cgroup namespace is locked at monitor startup - can't change */
        if (reboot_cfg.conf.force_cgroupv1 != old_force_cgv1) {
          printf("\nforce_cgroupv1 changed but requires a full stop/start to take effect\n");
          reboot_cfg.conf.force_cgroupv1 = old_force_cgv1;
        }
        *cfg = reboot_cfg;
        /* Restore mount point for img-based containers */
        if (cfg->conf.img_mount_point[0]) {
        }
      }
    }

    cfg->rt.reboot_cycle = true;
    clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

    /* Refresh ns_inode: new container has a new PID namespace inode.
     * Without this, virtualize_update's PID-recycling guard rejects
     * all writes after the first reboot cycle (stale inode != new pid ns). */
    cfg->rt.ns_inode = get_pid_ns_inode(cfg->rt.container_pid);
    if (cfg->rt.foreground)
      log_silent = 1;

    goto reboot_loop;
  }

  /* Not a reboot - check if external command is handling cleanup */
  if (is_external_lock_active(cfg->conf.container_name)) {
    write_monitor_debug_log(cfg->conf.container_name,
                            "External command lock detected - yielding "
                            "cleanup to CLI");
    goto monitor_cleanup_and_exit;
  }

  /* Normal exit - monitor does cleanup */
  write_monitor_debug_log(cfg->conf.container_name, "Monitor performing cleanup");

  cleanup_container_resources(cfg, false);

monitor_cleanup_and_exit:
  /* Free dynamically allocated configuration members before exit */
  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}
