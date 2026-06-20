/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/*
 * apply_capability_hardening()
 *
 * Drops dangerous capabilities from the bounding set to reduce the container's
 * attack surface.
 *
 * In Standard Mode (hw_access=0), we drop several sensitive capabilities.
 * In Hardware Mode (hw_access=1), we preserve most to ensure full
 * low-level hardware access (USB, Serial, Bluetooth, Flashing).
 */
void apply_capability_hardening(int hw_access, int privileged_mask) {
  if (privileged_mask & PRIV_NOCAPS) {
    log_info("[SEC] --privileged=nocaps: skipping capability drops.");
    return;
  }
  /* Universal drops - even in hardware mode, there's no legitimate use
   * for CAP_SYS_MODULE inside a container (kernel module loading).
   * CAP_SYS_BOOT is intentionally preserved - it is required for in-container
   * reboot(2) to work inside a PID namespace without rebooting the host.
   * CAP_MKNOD is intentionally PRESERVED: nested container runtimes
   * (Docker-in-Docker, LXC-in-LXC) need mknod to create /dev nodes for
   * their own containers.  /proc/partitions is nullified in the jail mask
   * to prevent host block-device enumeration. */
  int universal_drops[] = {CAP_SYS_MODULE, -1};
  int total_dropped = 0;

  for (int i = 0; universal_drops[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, universal_drops[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] Failed to drop universal cap %d: %s",
                 universal_drops[i], strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  if (hw_access) {
    log_info(
        "[SEC] Hardware Mode: preserved bounding set (dropped %d universal "
        "caps).",
        total_dropped);
    return;
  }

  /* Standard Hardening Tier: drop capabilities that affect host stability
   * or allow escaping the container's isolation. */
  int caps_to_drop[] = {
      CAP_SYS_RAWIO,       /* Raw hardware access (I/O ports, memory) */
      CAP_SYS_PTRACE,      /* Process tracing/injection across namespaces */
      CAP_SYS_PACCT,       /* Process accounting */
      CAP_SYSLOG,          /* log */
      CAP_MAC_ADMIN,       /* Mandatory Access Control policy modification */
      CAP_MAC_OVERRIDE,    /* Bypass MAC policies */
      CAP_WAKE_ALARM,      /* Affect host power management / wakeups */
      CAP_BLOCK_SUSPEND,   /* Affect host power management / sleep */
      CAP_AUDIT_READ,      /* Read kernel audit logs */
      CAP_DAC_READ_SEARCH, /* Bypass file read/directory search permissions -
                            * the other half of the Shocker escape: combined
                            * with open_by_handle_at it allows reading any
                            * file on the host outside the mount namespace. */
      -1};

  for (int i = 0; caps_to_drop[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, caps_to_drop[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] Failed to drop cap %d: %s", caps_to_drop[i],
                 strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  log_info("[SEC] Bounding set hardened (dropped %d caps).", total_dropped);
}

int internal_boot(struct config *cfg) {
  /* Defensive check: ensure configuration is valid */
  if (!cfg) {
    log_error("internal_boot received NULL configuration.");
    return -1;
  }

  /* Pre-open the container log file before namespace isolation / pivot_root.
   * The FD survives mount namespace changes, ensuring all post-pivot logs
   * (X11 bridge, bind mounts, init exec) are captured in the host log. */
  open_container_log(cfg);

  /* NET_NONE: bring up loopback in the isolated network namespace */
  if (cfg->isolation_network) {
    nl_ctx_t *nlctx = nl_open();
    if (nlctx) {
      nl_link_up(nlctx, "lo");
      nl_close(nlctx);
      log_info("[NET] Isolated network namespace: loopback up");
    }
  }

  /* 0. Boot Guard: Ensure name is present and unique.
   * This is a critical security check to prevent anonymous or conflicting
   * containers from booting, even if the CLI checks were bypassed. */
  if (!cfg->container_name[0]) {
    log_error("CRITICAL: Boot aborted — container name is empty.");
    goto boot_fail;
  }

  pid_t existing_pid = 0;
  if (is_container_running(cfg, &existing_pid)) {
    /* If we find ourselves in the pidfile, it's not a conflict, it's just us
     * being tracked early (which is fine). */
    if (existing_pid != getpid()) {
      log_error(
          "CRITICAL: Boot aborted — name '%s' is already in use by PID %d.",
          cfg->container_name, existing_pid);
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
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
    log_error("Failed to make / private: %s", strerror(errno));
    goto boot_fail;
  }

  /* 3. Setup volatile overlay INSIDE the container's mount namespace.
   * This MUST happen here (not in parent) so the overlay's connection to
   * its lowerdir (e.g. a loop-mounted image) survives mount privatization. */
  if (cfg->volatile_mode) {
    if (setup_volatile_overlay(cfg) < 0) {
      log_error("Failed to setup volatile overlay.");
      goto boot_fail;
    }
  }

  /* 4. Bind mount rootfs to itself (required for pivot_root) */
  if (mount(cfg->img_mount_point, cfg->img_mount_point, NULL,
            MS_BIND | MS_REC, NULL) < 0) {
    log_error("Failed to bind mount rootfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* 5. Set working directory to rootfs (required before pivot_root) */
  if (chdir(cfg->img_mount_point) < 0) {
    log_error("Failed to chdir to '%s': %s", cfg->img_mount_point,
              strerror(errno));
    goto boot_fail;
  }

  /* 6. Read UUID from /run/.boot-uuid (written by monitor via procfs) */
  if (cfg->uuid[0] == '\0') {
    read_file("run/.boot-uuid", cfg->uuid, sizeof(cfg->uuid));
  }
  unlink("run/.boot-uuid");

  /* 7. Pre-create standard directories in one loop to reduce syscalls */
  const char *dirs_to_create[] = {".old_root", "proc", "sys", "run", "tmp"};
  int dir_creation_failed = 0;
  for (size_t i = 0; i < sizeof(dirs_to_create) / sizeof(dirs_to_create[0]);
       i++) {
    if (mkdir(dirs_to_create[i], 0755) < 0 && errno != EEXIST) {
      log_error("Failed to create '%s': %s", dirs_to_create[i],
                strerror(errno));
      /* .old_root is critical for pivot_root, track if it fails */
      if (strcmp(dirs_to_create[i], ".old_root") == 0) {
        dir_creation_failed = 1;
      }
    }
  }
  if (dir_creation_failed) {
    log_error("Failed to create critical directory .old_root");
    goto boot_fail;
  }

  /* 8. Setup /dev (device nodes, devtmpfs) */
  if (setup_dev(".", cfg->hw_access, cfg->gpu_mode, cfg->privileged_mask) < 0) {
    log_error("Failed to setup /dev.");
    goto boot_fail;
  }

  /* 9. Log hardware access mode (BEFORE pivot_root) */
  if (!cfg->reboot_cycle) {
    if (cfg->hw_access)
      log_info("Setting up hardware access...");
    else if (cfg->gpu_mode)
      log_info("Setting up GPU-only access...");
    else
      log_info("Hardware access disabled: using isolated tmpfs...");
  }

  /* 10. Mount virtual filesystems (proc, sys) */
  if (domount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) <
      0) {
    log_error("Failed to mount procfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* Mount /sys */
  if (domount("sysfs", "sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) <
      0) {
    log_error("Failed to mount sysfs: %s", strerror(errno));
    goto boot_fail;
  }

  /* 10. Pre-create the cgroup mountpoint while /sys is still RW.
   * This allows us to mount cgroups onto it later even after /sys is RO. */
  mkdir_p("sys/fs/cgroup", 0755);

  if (cfg->hw_access && cfg->foreground) {
    /* DYNAMIC HARDWARE HOLES: Instead of hardcoding, we iterate through
     * everything in /sys and 'pin' subdirectories as independent RW mounts.
     * This ensures 100% hardware visibility (devices, bus, class, block, etc)
     * even after we remount the top-level /sys as RO for systemd's benefit. */
    _cleanup_closedir_ DIR *d = opendir("sys");
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
          continue;

        char subpath[PATH_MAX];
        snprintf(subpath, sizeof(subpath), "sys/%s", de->d_name);

        struct stat st;
        if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
          if (mount(subpath, subpath, NULL, MS_BIND | MS_REC, NULL) < 0) {
            /* Ignore errors for files or pseudo-dirs that can't be mounted */
          }
        }
      }
    }
  } else if (!cfg->hw_access) {
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
    if (mount("sys/devices/virtual/net", "sys/devices/virtual/net", NULL,
              MS_BIND | MS_REC, NULL) < 0) {
      log_warn("Failed to bind-mount network devices in isolated /sys "
               "(networking may be limited)");
    }
  }

  /* Remount /sys as RO for systemd's benefit, but ONLY if we are in
   * foreground mode + systemd (where we used pinned sub-mounts) or if
   * hw_access is disabled entirely. In background mode or non-systemd
   * hw_access mode, we leave /sys RW. */
  if (!cfg->hw_access || (cfg->foreground)) {
    if (mount(NULL, "sys", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) < 0) {
      log_warn("Failed to remount /sys as read-only: %s", strerror(errno));
    }
  }

  /* 11. Setup Cgroups AFTER locking down /sys.
   * Mounting onto a directory on a RO parent is allowed for root, and it
   * ensures the sub-mount (tmpfs) is RW and independent of the parent's RO. */
  if (setup_cgroups(cfg->force_cgroupv1) < 0) {
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
  if (mount(cfg->console.name, "dev/console", NULL, MS_BIND, NULL) < 0)
    log_warn("Failed to bind mount console '%s': %s", cfg->console.name,
             strerror(errno));

  /* 15. Custom bind mounts */
  setup_custom_binds(cfg, ".");

  /* 16. pivot_root with MS_MOVE+chroot fallback for ramfs/rootfs environments
   * (e.g. Android recovery) where pivot_root(2) always returns EINVAL because
   * the kernel refuses to pivot when new_root is on the same underlying fs as
   * the current root (ramfs has no backing device, self-bind doesn't help).
   * MS_MOVE atomically relocates the new root onto / and chroot(2) locks us
   * in - exactly what switch_root(8) does internally. */
  int used_ms_move = 0;
  if (is_ramfs("/")) {
    log_info("Detected rootfs/ramfs root - automatically falling back to "
             "MS_MOVE+chroot");
    used_ms_move = 1;
    if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
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

  /* 16b. Apply deferred mount propagation settings.
   * Switch to MS_SHARED only after relocation is complete. */
  if (cfg->privileged_mask & PRIV_SHARED) {
    if (mount(NULL, "/", NULL, MS_REC | MS_SHARED, NULL) < 0) {
      log_warn("[SEC] Failed to apply MS_SHARED propagation: %s",
               strerror(errno));
    } else {
      log_info("[SEC] Root mount propagation set to SHARED.");
    }
  }

  /* 17. Setup devpts (must be after pivot_root for newinstance) */
  setup_devpts(cfg->hw_access);

  /* Apply jail mask after pivot_root for correct path resolution */
  apply_jail_mask(cfg->hw_access, cfg->privileged_mask);

  /* 17b. Resource Visibility Virtualization
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

  /* Log bind mounts and boot (after hw-access logs for clean ordering) */
  if (!cfg->reboot_cycle) {
    if (cfg->bind_count > 0)
      log_info("Setting up %d custom bind mount(s)...", cfg->bind_count);
    log_info("Booting '%s' (init: %s)...", cfg->container_name,
             cfg->custom_init[0] ? cfg->custom_init : DEFAULT_INIT);
  }

  /* 18. Write identity markers for PID discovery (AFTER logs to ensure CLI
   * parent sees them before exiting background mode). */
  mkdir(FORK_MARKER, 0755);
  if (cfg->uuid[0] != '\0') {
    char uuid_path[PATH_MAX];
    snprintf(uuid_path, sizeof(uuid_path), FORK_MARKER "/%s", cfg->uuid);
    write_file(uuid_path, ""); /* empty UUID marker */
  }

  /* Save a normalized copy of the config inside /run for metadata recovery. */
  if (config_save(FORK_MARKER "/container.config", cfg) < 0) {
    log_warn("Boot: Failed to save internal configuration backup");
  }

  write_file(FORK_MARKER "/name", cfg->container_name);

  if (cfg->img_mount_point[0])
    write_file(FORK_MARKER "/mount", cfg->img_mount_point);

  /* Legacy compatibility: write version to the marker directory root */
  write_file(FORK_MARKER "/version", PROJECT_VERSION);
  if (cfg->foreground) {
    printf(C_BOLD C_WHITE "\r\n(to exit from the foreground mode, press "
                          "CTRL+ALT+Q)\r\n" C_RESET);
    fflush(stdout);
  }
  printf("\r\n");
  fflush(stdout);

  /* 19. Cleanup .old_root (skip when MS_MOVE fallback was used - there is no
   * old root mountpoint to detach in that path). */
  if (!used_ms_move) {
    if (umount2("/.old_root", MNT_DETACH) < 0)
      log_warn("Failed to unmount .old_root: %s", strerror(errno));
    else
      rmdir("/.old_root");
  } else {
    rmdir("/.old_root");
  }

  /* 20. Clear environment and set container defaults */
  clearenv();
  setenv("container", PROJECT_NAME, 1);
  if (cfg->img_mount_point[0])
    setenv("RUNTIME_MOUNT_PATH", cfg->img_mount_point, 1);

  /* 20b. Apply security hardening (capabilities)
   * Apply security hardening (capabilities and seccomp)
   * This is done at the very end to ensure all setup tasks that might need
   * privileges (like chown/chmod or mknod) are finished. */
  seccomp_apply_minimal(cfg->privileged_mask);
  android_seccomp_setup(cfg->block_nested_ns &&
      !(cfg->privileged_mask & PRIV_NOSEC),
      cfg->privileged_mask);

  apply_capability_hardening(cfg->hw_access, cfg->privileged_mask);

  /* 21. Redirect standard I/O to /dev/console */
  int console_fd = open("/dev/console", O_RDWR);
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
      if (ioctl(console_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col == 0 &&
          ws.ws_row == 0) {
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

  /* 22. EXEC INIT */
  char *init_bin =
      cfg->custom_init[0] ? cfg->custom_init : (char *)DEFAULT_INIT;
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
    if ((unsigned long)_cgsfs.f_type == (unsigned long)CGROUP2_SUPER_MAGIC) {
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=1";
    } else {
      /* tmpfs root → legacy or hybrid layout mounted by setup_cgroups */
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=0";
      init_args[argc++] = (char *)"systemd.legacy_systemd_cgroup_controller=1";
    }
  }
  /* statfs failure → leave systemd to probe on its own */

  init_args[argc] = NULL;

  if (execve(init_bin, init_args, environ) < 0) {
    log_error("Failed to execute %s: %s", init_bin, strerror(errno));
    log_die("Container boot failed. Please ensure the rootfs path is correct "
            "and contains a valid %s binary.",
            init_bin);
  }

boot_fail:
  close_container_log();
  return -1;
}
