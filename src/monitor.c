/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* ---------------------------------------------------------------------------
 * monitor_run - Supervisor process for a single container instance.
 *
 * Called immediately after fork() in start_rootfs(). Never returns - always
 * ends with _exit(). sync_pipe_write is the write-end of the parent sync
 * pipe; the monitor (or its intermediate child) writes the container init PID
 * through it on the first boot cycle, then closes it.
 * ---------------------------------------------------------------------------*/
void monitor_run(struct config *cfg, int sync_pipe_write) {
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

  /* Unshare namespaces - Monitor enters new UTS, IPC, and optionally Cgroup
   * namespaces immediately. PID namespace is NOT unshared here because
   * unshare(CLONE_NEWPID) can only be called once per process. Instead,
   * each boot/reboot cycle forks an intermediate that creates a fresh
   * PID namespace. */
  int ns_flags = CLONE_NEWUTS | CLONE_NEWIPC;

  /* Adaptive Cgroup Namespace (introduced in Linux 4.6).
   *
   * CGROUP SELECTION: Only enable cgroupns when V2 is active.
   * If --force-cgroupv1 is set, we skip cgroupns so setup_cgroups()
   * has full rights to create named V1 hierarchies from the host context. */
  int cg_ns_ok = (access("/proc/self/ns/cgroup", F_OK) == 0) &&
                 (cgroup_host_is_v2() && !cfg->force_cgroupv1);
  if (cg_ns_ok) {
    /* To get isolation from a cgroup namespace, we must be in a sub-cgroup
     * BEFORE we unshare. If we are in the root '/', the namespace root
     * will be the host's root, providing zero isolation.
     * We use a container-specific path to avoid conflicts. */
    if (access("/sys/fs/cgroup/cgroup.procs", F_OK) == 0) {
      char safe_name[256];
      sanitize_container_name(cfg->container_name, safe_name,
                              sizeof(safe_name));

      /* v2: enable requested controllers top-down BEFORE mkdir.
       * Controllers only appear in a child cgroup if the parent's
       * subtree_control has them enabled first. Walk two levels:
       * /sys/fs/cgroup -> /sys/fs/cgroup/ds-fork */
      if (cfg->memory_limit || cfg->cpu_quota || cfg->pids_limit) {
        /* Build enable string with snprintf offsets instead of strncat to
         * avoid truncation. Use cg_word_in_list() for exact word-boundary
         * matching to prevent false positives (e.g. matching "cpuset"
         * when looking for "cpu"). */
        char enable[64] = {0};
        char buf[256];
        int eoff = 0;
        if (read_file("/sys/fs/cgroup/cgroup.controllers", buf, sizeof(buf)) >
            0) {
          if (cfg->memory_limit && cg_word_in_list(buf, "memory")) {
            int n = snprintf(enable + eoff, sizeof(enable) - (size_t)eoff,
                             "%s+memory", eoff ? " " : "");
            if (n > 0)
              eoff += n;
          }
          if (cfg->cpu_quota && cg_word_in_list(buf, "cpu")) {
            int n = snprintf(enable + eoff, sizeof(enable) - (size_t)eoff,
                             "%s+cpu", eoff ? " " : "");
            if (n > 0)
              eoff += n;
          }
          if (cfg->pids_limit && cg_word_in_list(buf, "pids")) {
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
      FILE *f = fopen(cg_procs, "we");
      if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
      }
    }
    ns_flags |= CLONE_NEWCGROUP;
  } else {
    /* Legacy kernel without force flag - skip cgroupns, run in host
     * cgroupns with full rights so setup_cgroups() can create named
     * v1 hierarchies. */
  }

  /* Apply resource limits. On v2 hosts this writes memory.max / cpu.max /
   * pids.max into the delegated cgroup. On v1 or --force-cgroupv1 the
   * function skips with a warning since v1 delegation is unreliable. */
  if (cgroup_apply_limits(cfg) < 0 &&
      (cfg->memory_limit || cfg->cpu_quota || cfg->pids_limit))
    log_warn("[CGROUP] Some resource limits could not be enforced.");

  if (unshare(ns_flags) < 0)
    log_die("unshare failed: %s", strerror(errno));

  int stdio_redirected = 0;

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

  /* First boot only: ensure no stale container with the same name is running
   */
  if (!cfg->reboot_cycle) {
    pid_t existing_pid = 0;
    if (is_container_running(cfg, &existing_pid)) {
      if (existing_pid != getpid()) {
        /*
         * Crucial Safety: Only kill the process if it's confirmed to be a
         * ds-fork container. This prevents killing random processes that
         * might have recycled the PID after the container died without
         * cleanup.
         */
        if (is_valid_container_pid(existing_pid)) {
          log_warn("Killing stale container with same name (PID %d)",
                   existing_pid);
          kill(existing_pid, SIGKILL);
          usleep(100000);
        }
      }
    }
  }

  /* Stdio handling for monitor in background mode (early redirection).
   * We must do this BEFORE forking the intermediate process, otherwise
   * the intermediate inherits the user's stdout/stderr (e.g. a pipe)
   * and holds it open indefinitely, causing CLI hangs in direct mode. */
  if (!cfg->foreground && !stdio_redirected) {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      /* Note: we don't redirect 1 and 2 here yet because we want to see
       * networking setup logs. We'll do a full redirect after the fork. */
      close(devnull);
    }
  }

  pid_t mid_pid = fork();
  if (mid_pid < 0)
    _exit(EXIT_FAILURE);

  if (mid_pid == 0) {
    /* INTERMEDIATE PROCESS
     * Create a fresh PID namespace (and NET namespace for NAT/none modes)
     * for this boot cycle. */
    int clone_flags = CLONE_NEWPID;
    if (cfg->net_mode != NET_HOST)
      clone_flags |= CLONE_NEWNET;

    if (unshare(clone_flags) < 0) {
      log_error("unshare(PID|NET) failed: %s", strerror(errno));
      _exit(EXIT_FAILURE);
    }

    pid_t init_pid = fork();
    if (init_pid < 0)
      _exit(EXIT_FAILURE);

    if (init_pid == 0) {
      /* CONTAINER INIT (PID 1 inside namespace) */
      close(sync_pipe[1]);
      _exit(internal_boot(cfg));
    }

    /* Intermediate: redirect stdio to /dev/null NOW (after forking init).
     * It only exists to wait for init and has no business talking to the
     * user's terminal or holding pipes open.
     *
     * BUG FIX: this redirect was previously placed BEFORE the fork(), which
     * caused init_pid to inherit /dev/null for fd 1 and fd 2. Every
     * log_info() call inside internal_boot() writes to stdout, so all boot
     * logs were silently swallowed by /dev/null - visible only in the log
     * file (which uses direct file I/O, not stdout). Moving the redirect
     * here means only the intermediate itself goes silent; internal_boot()
     * retains the original terminal fds until it redirects to /dev/console
     * at its own step 24. */
    if (!cfg->foreground) {
      int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);
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
  cfg->ns_inode = get_pid_ns_inode(cfg->container_pid);

  /* Ensure monitor is not sitting inside any mount point */
  if (chdir("/") < 0) {
    log_warn("Failed to chdir to /: %s", strerror(errno));
  }

  /* Stdio handling for monitor in background mode (first boot only) */
  if (!cfg->foreground && !stdio_redirected) {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
      close(devnull);
    }
    stdio_redirected = 1;
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
    sigprocmask(SIG_BLOCK, &mask, NULL);
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    while (1) {
      pid_t r = waitpid(mid_pid, &status, WNOHANG);
      if (r == mid_pid)
        break;
      if (r < 0 && errno != EINTR)
        break;

      /* HOST mode: resolve container_pid via /proc scan using UUID.
       * Poll until we have a valid PID, then capture ns_inode once. */
      if (cfg->container_pid <= 0 && cfg->uuid[0] != '\0') {
        pid_t p = find_container_init_pid(cfg->uuid);
        if (p > 0) {
          cfg->container_pid = p;
          cfg->ns_inode = get_pid_ns_inode(p);
          write_monitor_debug_log(cfg->container_name,
                                  "[VIRT] resolved container_pid=%d "
                                  "ns_inode=%lu from /proc",
                                  (int)p, cfg->ns_inode);
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

    if (sfd >= 0)
      close(sfd);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
  }

  /* Log what monitor saw */
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == REBOOT_EXIT) {
      write_monitor_debug_log(cfg->container_name, "Detected internal REBOOT");
    } else {
      write_monitor_debug_log(cfg->container_name,
                              "Detected container SHUTDOWN (exit: %d)", code);
    }
  } else if (WIFSIGNALED(status)) {
    write_monitor_debug_log(cfg->container_name,
                            "Intermediate killed by signal: %d (%s)",
                            WTERMSIG(status), strsignal(WTERMSIG(status)));
  }

  /* Reboot detection (internal reboot) */
  if (WIFEXITED(status) && WEXITSTATUS(status) == REBOOT_EXIT) {
    /* Check for external lock - if exists, abort reboot and let CLI handle it
     */
    if (is_external_lock_active(cfg->container_name)) {
      write_monitor_debug_log(
          cfg->container_name,
          "External command lock detected - aborting internal reboot");
      goto monitor_cleanup_and_exit;
    }

    if (cfg->foreground) {
      printf("\n" C_WHITE PROJECT_NAME " " PROJECT_VERSION " : "
             "Container " C_GREEN "%s" C_RESET C_WHITE " is now Rebooting" C_RESET "\n",
             cfg->container_name);
      fflush(stdout);
    }

    /* Synchronize container_pid in Monitor via /proc scan */
    if (cfg->uuid[0] != '\0') {
      pid_t new_pid = find_container_init_pid(cfg->uuid);
      if (new_pid > 0)
        cfg->container_pid = new_pid;
    }

    /* Write UUID to container /run (via procfs) so internal_boot can read it
     * across the pivot_root boundary without touching user's rootfs. */
    if (!cfg->volatile_mode && cfg->container_pid > 0) {
      char run_dir[PATH_MAX];
      snprintf(run_dir, sizeof(run_dir), "/proc/%d/root/run",
               cfg->container_pid);
      mkdir(run_dir, 0755);
      int fd = safe_openat_proc(cfg->container_pid, "run/.boot-uuid",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        size_t ulen = strlen(cfg->uuid);
        write_all(fd, cfg->uuid, ulen);
        close(fd);
      }
    }

    /* Reload from workspace (canonical path the user edits) */
    {
      free_config_binds(cfg);
      int old_force_cgv1 = cfg->force_cgroupv1;

      struct config reboot_cfg = *cfg;
      if (config_load_by_name(cfg->container_name, &reboot_cfg) == 0) {
        /* Cgroup namespace is locked at monitor startup - can't change */
        if (reboot_cfg.force_cgroupv1 != old_force_cgv1) {
          printf("\n" C_BOLD C_YELLOW "force_cgroupv1 changed but "
                 "requires a full stop/start to take effect" C_RESET "\n");
          reboot_cfg.force_cgroupv1 = old_force_cgv1;
        }
        *cfg = reboot_cfg;
        /* Restore mount point for img-based containers */
        if (cfg->img_mount_point[0]) {
        }
      }
    }

    cfg->reboot_cycle = 1;
    clock_gettime(CLOCK_BOOTTIME, &cfg->start_time);

    /* Refresh ns_inode: new container has a new PID namespace inode.
     * Without this, virtualize_update's PID-recycling guard rejects
     * all writes after the first reboot cycle (stale inode != new pid ns). */
    cfg->ns_inode = get_pid_ns_inode(cfg->container_pid);
    if (cfg->foreground)
      log_silent = 1;

    goto reboot_loop;
  }

  /* Not a reboot - check if external command is handling cleanup */
  if (is_external_lock_active(cfg->container_name)) {
    write_monitor_debug_log(cfg->container_name,
                            "External command lock detected - yielding "
                            "cleanup to CLI");
    goto monitor_cleanup_and_exit;
  }

  /* Normal exit - monitor does cleanup */
  write_monitor_debug_log(cfg->container_name, "Monitor performing cleanup");

  /* Before cleaning up the container's cgroup subtree, move the
   * monitor process itself back to the root cgroup.  The monitor wrote its
   * own PID into /sys/fs/cgroup/ds-fork/<name>/ at start (for cgroup
   * namespace isolation).  If it is still in that cgroup when
   * cgroup_cleanup_container() calls rmdir, the kernel sees a non-empty
   * cgroup and returns EBUSY - the directory is never removed.
   *
   * Writing our PID to the root cgroup.procs atomically migrates us out.
   * This is safe: the monitor is about to _exit() anyway. */
  {
    int root_fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (root_fd >= 0) {
      char pid_s[32];
      int len = snprintf(pid_s, sizeof(pid_s), "%d", (int)getpid());
      if (write(root_fd, pid_s, len) < 0) {
      }
      close(root_fd);
    }
  }

  cleanup_container_resources(cfg, 0, 0);

monitor_cleanup_and_exit:
  /* Free dynamically allocated configuration members before exit */
  config_free(cfg);
  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}
