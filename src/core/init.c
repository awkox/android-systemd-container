#include "asc.h"

void internal_boot(cfg_t *cfg) {
  /* Defensive check: ensure configuration is valid */
  if (!cfg) {
    log_error("internal_boot received NULL configuration.");
    return;
  }

  /* Pre-open the container log file before namespace isolation / pivot_root.
   * The FD survives mount namespace changes, ensuring all post-pivot logs
   * (X11 bridge, bind mounts, init exec) are captured in the host log. */
  open_container_log(cfg);

  /* NET_NONE: bring up loopback in the isolated network namespace */
  if (cfg->conf.isolation_network) {
    auto_free nl_ctx_t *nlctx = nl_open();
    if (nlctx) {
      nl_link_up(nlctx, "lo");
      close(nlctx->fd);
      log_info("[NET] Isolated network namespace: loopback up");
    }
  }

  /* 0. Boot Guard: Ensure name is present and unique.
   * This is a critical security check to prevent anonymous or conflicting
   * containers from booting, even if the CLI checks were bypassed. */
  if (!cfg->conf.container_name[0]) {
    log_error("CRITICAL: Boot aborted — container name is empty.");
    goto boot_fail;
  }

  pid_t existing_pid = 0;
  if (is_container_running(cfg->conf.uuid, &existing_pid)) {
    /* If we find ourselves in the pidfile, it's not a conflict, it's just us
     * being tracked early (which is fine). */
    if (existing_pid != getpid()) {
      log_error(
          "CRITICAL: Boot aborted — name '%s' is already in use by PID %d.",
          cfg->conf.container_name, existing_pid);
      goto boot_fail;
    }
  }

  /* 1. Isolated mount namespace */
  if (unshare(CLONE_NEWNS) < 0) {
    log_error("Failed to unshare mount namespace: %s", strerror(errno));
    goto boot_fail;
  }

  /* 2. Make all mounts private to avoid leaking to host.
   * We ALWAYS start with MS_PRIVATE because MS_SHARED breaks pivot_root/MS_MOVE
   * fallbacks on some kernels (e.g. Android rootfs). We will switch to
   * MS_SHARED after the rootfs relocation if requested. */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    log_error("Failed to make / private: %s", strerror(errno));
    goto boot_fail;
  }

  /* 3. Setup volatile overlay INSIDE the container's mount namespace.
   * This MUST happen here (not in parent) so the overlay's connection to
   * its lowerdir (e.g. a loop-mounted image) survives mount privatization. */
  if (cfg->conf.volatile_mode) {
    if (setup_volatile_overlay(cfg) < 0) {
      log_error("Failed to setup volatile overlay.");
      goto boot_fail;
    }
  }

  /* 4. Bind mount rootfs to itself (required for pivot_root) */
  if (mount(cfg->conf.img_mount_point, cfg->conf.img_mount_point, nullptr,
            MS_BIND | MS_REC, nullptr) < 0) {
    log_error("Failed to bind mount rootfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* 5. Set working directory to rootfs (required before pivot_root) */
  if (chdir(cfg->conf.img_mount_point) < 0) {
    log_error("Failed to chdir to '%s': %s", cfg->conf.img_mount_point,
              strerror(errno));
    goto boot_fail;
  }

  /* 6. Read UUID from /run/.boot-uuid (written by monitor via procfs) */
  if (cfg->conf.uuid[0] == '\0') {
    read_file("run/.boot-uuid", cfg->conf.uuid, sizeof(cfg->conf.uuid));
  }
  unlink("run/.boot-uuid");

  /* 7. Pre-create standard directories in one loop to reduce syscalls */
  const char *dirs_to_create[] = {".old_root", "proc", "sys", "run", "tmp"};
  bool dir_creation_failed = false;
  for (size_t i = 0; i < ARRAY_SIZE(dirs_to_create); i++) {
    if (mkdir(dirs_to_create[i], 0755) < 0 && errno != EEXIST) {
      log_error("Failed to create '%s': %s", dirs_to_create[i],
                strerror(errno));
      /* .old_root is critical for pivot_root, track if it fails */
      if (strcmp(dirs_to_create[i], ".old_root") == 0) {
        dir_creation_failed = true;
      }
    }
  }
  if (dir_creation_failed) {
    log_error("Failed to create critical directory .old_root");
    goto boot_fail;
  }

  /* 8. Setup /dev (device nodes, devtmpfs) */
  if (setup_dev(".", cfg->conf.hw_access, cfg->conf.gpu_mode, cfg->conf.privileged_mask) < 0) {
    log_error("Failed to setup /dev.");
    goto boot_fail;
  }

  /* 9. Log hardware access mode (BEFORE pivot_root) */
  if (!cfg->rt.reboot_cycle) {
    if (cfg->conf.hw_access)
      log_info("Setting up hardware access...");
    else if (cfg->conf.gpu_mode)
      log_info("Setting up GPU-only access...");
    else
      log_info("Hardware access disabled: using isolated tmpfs...");
  }

  /* 10. Mount virtual filesystems (proc, sys) */
  if (domount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) <
      0) {
    log_error("Failed to mount procfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* Mount /sys */
  if (domount("sysfs", "sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) <
      0) {
    log_error("Failed to mount sysfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* 10. Pre-create the cgroup mountpoint while /sys is still RW.
   * This allows us to mount cgroups onto it later even after /sys is RO. */
  mkdir_p("sys/fs/cgroup", 0755);

  if (cfg->conf.hw_access && cfg->rt.foreground) {
    /* DYNAMIC HARDWARE HOLES: Instead of hardcoding, we iterate through
     * everything in /sys and 'pin' subdirectories as independent RW mounts.
     * This ensures 100% hardware visibility (devices, bus, class, block, etc)
     * even after we remount the top-level /sys as RO for systemd's benefit. */
    auto_closedir DIR *d = opendir("sys");
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.')
          continue;

        char subpath[PATH_MAX];
        snprintf(subpath, sizeof(subpath), "sys/%s", de->d_name);

        struct stat st;
        if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
          if (mount(subpath, subpath, nullptr, MS_BIND | MS_REC, nullptr) < 0) {
            /* Ignore errors for files or pseudo-dirs that can't be mounted */
          }
        }
      }
    }
  } else if (!cfg->conf.hw_access) {
    /* Hardware isolation: network only mixed mode */
    if (mkdir("sys/devices", 0755) < 0 && errno != EEXIST) {
      log_warn("Failed to create sys/devices directory: %s", strerror(errno));
    }
    if (mkdir("sys/devices/virtual", 0755) < 0 && errno != EEXIST) {
      log_warn("Failed to create sys/devices/virtual directory: %s",
               strerror(errno));
    }
    if (mkdir("sys/devices/virtual/net", 0755) < 0 && errno != EEXIST) {
      log_warn("Failed to create sys/devices/virtual/net directory: %s",
               strerror(errno));
    }

    /* Fix: Instead of mounting a fresh sysfs (which creates a recursive tree),
     * we bind-mount the existing net devices path from our own sysfs mount.
     * This keeps the symlink at /sys/class/net/eth0 valid while pinning the
     * path as an independent mount point that can survive isolation and
     * provide RW access if needed. */
    if (mount("sys/devices/virtual/net", "sys/devices/virtual/net", nullptr,
              MS_BIND | MS_REC, nullptr) < 0) {
      log_warn("Failed to bind-mount network devices in isolated /sys "
               "(networking may be limited)");
    }
  }

  /* Remount /sys as RO for systemd's benefit, but ONLY if we are in
   * foreground mode + systemd (where we used pinned sub-mounts) or if
   * hw_access is disabled entirely. In background mode or non-systemd
   * hw_access mode, we leave /sys RW. */
  if (!cfg->conf.hw_access || cfg->rt.foreground) {
    if (mount(nullptr, "sys", nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) < 0) {
      log_warn("Failed to remount /sys as read-only: %s", strerror(errno));
    }
  }

  /* 11. Setup Cgroups AFTER locking down /sys.
   * Mounting onto a directory on a RO parent is allowed for root, and it
   * ensures the sub-mount (tmpfs) is RW and independent of the parent's RO. */
  if (setup_cgroups(cfg->conf.force_cgroupv1) < 0) {
    log_error("Failed to setup container cgroups.");
    goto boot_fail;
  }

  if (domount("tmpfs", "run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755") < 0) {
    log_error("Failed to mount tmpfs at /run: %s", strerror(errno));
    goto boot_fail;
  }

  /* 13. Setup /tmp: always mount a fresh isolated tmpfs.
   * The X11 socket lives in /run/.X11-unix so systemd's tmp.mount
   * cannot interfere with it. */
  if (domount("tmpfs", "tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777") < 0)
    log_warn("Failed to mount tmpfs at /tmp: %s", strerror(errno));

  /* 14. Bind-mount console BEFORE pivot_root (host pts still visible). */
  if (mount(cfg->rt.console.name, "dev/console", nullptr, MS_BIND, nullptr) < 0)
    log_warn("Failed to bind mount console '%s': %s", cfg->rt.console.name,
             strerror(errno));

  /* 15. pivot_root with MS_MOVE+chroot fallback for ramfs/rootfs environments
   * (e.g. Android recovery) where pivot_root(2) always returns EINVAL because
   * the kernel refuses to pivot when new_root is on the same underlying fs as
   * the current root (ramfs has no backing device, self-bind doesn't help).
   * MS_MOVE atomically relocates the new root onto / and chroot(2) locks us
   * in - exactly what switch_root(8) does internally. */
  bool used_ms_move = false;
  if (is_ramfs("/")) {
    log_info("Detected rootfs/ramfs root - automatically falling back to "
             "MS_MOVE+chroot");
    used_ms_move = true;
    if (mount(".", "/", nullptr, MS_MOVE, nullptr) < 0) {
      log_error("MS_MOVE fallback failed: %s", strerror(errno));
      goto boot_fail;
    }
    if (chroot(".") < 0) {
      log_error("chroot(\".\") after MS_MOVE failed: %s", strerror(errno));
      goto boot_fail;
    }
  } else if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
    log_error("pivot_root failed: %s", strerror(errno));
    goto boot_fail;
  }

  if (chdir("/") < 0) {
    log_error("chdir(\"/\") after pivot_root failed: %s", strerror(errno));
    goto boot_fail;
  }

  /* 15b. Apply deferred mount propagation settings.
   * Switch to MS_SHARED only after relocation is complete. */
  if (cfg->conf.privileged_mask & PRIV_SHARED) {
    if (mount(nullptr, "/", nullptr, MS_REC | MS_SHARED, nullptr) < 0) {
      log_warn("[SEC] Failed to apply MS_SHARED propagation: %s",
               strerror(errno));
    } else {
      log_info("[SEC] Root mount propagation set to SHARED.");
    }
  }

  /* 16. Setup devpts (must be after pivot_root for newinstance) */
  setup_devpts(cfg->conf.hw_access);

  /* Apply jail mask after pivot_root for correct path resolution */
  apply_jail_mask(cfg->conf.hw_access, cfg->conf.privileged_mask);

  /* 16b. Resource Visibility Virtualization
   * Always runs: uptime/loadavg are fundamental container features.
   * CPU/RAM spoofing is selectively enabled only when cgroup limits are set. */
  if (is_mountpoint("/proc")) {
    if (virtualize_init(cfg) < 0)
      log_warn(
          "[VIRT] Initialization failed, continuing without virtualization.");
  } else {
    log_warn("[VIRT] /proc not mounted, skipping virtualization.");
  }

  if (sethostname("(none)", 6) < 0) {
    log_warn("Failed to reset hostname: %s", strerror(errno));
  }

  /* Log boot (after hw-access logs for clean ordering) */
  if (!cfg->rt.reboot_cycle) {
    log_info("Booting '%s' (init: %s)...", cfg->conf.container_name,
             cfg->conf.custom_init[0] ? cfg->conf.custom_init : DEFAULT_INIT);
  }

  /* 17. Write identity markers for PID discovery (AFTER logs to ensure CLI
   * parent sees them before exiting background mode). */
  mkdir(FORK_MARKER, 0755);
  if (cfg->conf.uuid[0] != '\0') {
    char uuid_path[PATH_MAX];
    snprintf(uuid_path, sizeof(uuid_path), FORK_MARKER "/%s", cfg->conf.uuid);
    write_file(uuid_path, ""); /* empty UUID marker */
  }

  /* Save a normalized copy of the config inside /run for metadata recovery. */
  if (config_save(FORK_MARKER "/container.config", cfg) < 0) {
    log_warn("Boot: Failed to save internal configuration backup");
  }

  write_file(FORK_MARKER "/name", cfg->conf.container_name);

  if (cfg->conf.img_mount_point[0])
    write_file(FORK_MARKER "/mount", cfg->conf.img_mount_point);

  /* Legacy compatibility: write version to the marker directory root */
  write_file(FORK_MARKER "/version", PROJECT_VERSION);
  if (cfg->rt.foreground) {
    printf("\r\n(to exit from the foreground mode, press CTRL+ALT+Q)\r\n");
    fflush(stdout);
  }
  printf("\r\n");
  fflush(stdout);

  /* 18. Cleanup .old_root (skip when MS_MOVE fallback was used - there is no
   * old root mountpoint to detach in that path). */
  if (!used_ms_move) {
    if (umount2("/.old_root", MNT_DETACH) < 0)
      log_warn("Failed to unmount .old_root: %s", strerror(errno));
    else
      rmdir("/.old_root");
  } else {
    rmdir("/.old_root");
  }

  /* 19. Clear environment and set container defaults */
  clearenv();
  setenv("container", PROJECT_NAME, 1);
  if (cfg->conf.img_mount_point[0])
    setenv("RUNTIME_MOUNT_PATH", cfg->conf.img_mount_point, 1);

  /* 19b. Apply security hardening (capabilities)
   * Apply security hardening (capabilities and seccomp)
   * This is done at the very end to ensure all setup tasks that might need
   * privileges (like chown/chmod or mknod) are finished. */
  seccomp_apply_minimal(cfg->conf.privileged_mask);
  android_seccomp_setup(cfg->conf.block_nested_ns &&
      !(cfg->conf.privileged_mask & PRIV_NOSEC),
      cfg->conf.privileged_mask);

  apply_capability_hardening(cfg->conf.hw_access, cfg->conf.privileged_mask);

  /* 20. Redirect standard I/O to /dev/console */
  const int console_fd = open("/dev/console", O_RDWR);
  if (console_fd >= 0) {
    if (terminal_set_stdfds(console_fd) < 0) {
      log_warn("Failed to redirect stdio to /dev/console");
      close(console_fd);
    } else {
      terminal_make_controlling(console_fd);

      /* Set a sane default window size on the console PTY if none was set.
       * The parent's console_monitor_loop will overwrite this with the
       * real host terminal size via SIGWINCH, but we need a reasonable
       * default so early boot output (before the parent syncs) is
       * properly aligned. Without this, programs like sudo that query
       * the terminal size get {0,0} and produce misaligned output. */
      struct winsize ws;
      if (ioctl(console_fd, TIOCGWINSZ, &ws) == 0
            && ws.ws_col == 0
            && ws.ws_row == 0) {
        ws.ws_row = 24;
        ws.ws_col = 80;
        ioctl(console_fd, TIOCSWINSZ, &ws);
      }

      /* Sticky permissions again just in case systemd's TTYReset stripped them
       */
      fchmod(console_fd, 0620);
      if (fchown(console_fd, 0, DEFAULT_TTY_GID) < 0) {
        /* best-effort, ignore EPERM */
      }
      if (console_fd > 2)
        close(console_fd);
    }
  }

  /* 21. EXEC INIT */
  char *init_bin =
      cfg->conf.custom_init[0] ? cfg->conf.custom_init : (char *)DEFAULT_INIT;
  char *init_args[16];
  int argc = 0;
  init_args[argc++] = init_bin;

  /* Tell systemd which cgroup hierarchy the container was actually set up
   * with.  We use statfs() on /sys/fs/cgroup (now the container root after
   * pivot_root) rather than guessing from kernel version.  setup_cgroups()
   * already decided the layout - we just reflect what it mounted:
   *   cgroup2fs  → unified (v2 only)  → unified_cgroup_hierarchy=1
   *   tmpfs      → legacy / hybrid    → unified_cgroup_hierarchy=0
   * This is exactly what LXC does via lxc.init.cmd. */
  struct statfs _cgsfs;
  if (statfs("/sys/fs/cgroup", &_cgsfs) == 0) {
    if (_cgsfs.f_type == CGROUP2_SUPER_MAGIC) {
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=1";
    } else {
      /* tmpfs root → legacy or hybrid layout mounted by setup_cgroups */
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=0";
      init_args[argc++] = (char *)"systemd.legacy_systemd_cgroup_controller=1";
    }
  }
  /* statfs failure → leave systemd to probe on its own */

  init_args[argc] = nullptr;

  if (execve(init_bin, init_args, environ) < 0) {
    log_error("Failed to execute %s: %s", init_bin, strerror(errno));
    log_die("Container boot failed. Please ensure the rootfs path is correct "
            "and contains a valid %s binary.",
            init_bin);
  }

boot_fail:
  close_container_log();
}
