#include "asc.h"

/* Universal masks - dangerous for ANY container regardless of HW mode */
static const char *universal_masks[] = {
  "/proc/sysrq-trigger",
  "/proc/kcore",
  "/proc/timer_list",
  nullptr
};

/* Universal nullify - paths where read access itself must be blocked
 * (bind-mount /dev/null over them). */
static const char *universal_nullify[] = {
  "/proc/partitions",
  nullptr
};

/* Kernel log paths blocked with FIFO instead of /dev/null:
 * rsyslogd imklog spins at 100% CPU when /dev/null returns immediate
 * EOF.  A FIFO with a persistent writer blocks read() indefinitely,
 * preventing both CPU spin and host kernel log leakage. */
static const char *kmsg_block_paths[] = {
  "/dev/kmsg",
  "/proc/kmsg",
  nullptr
};

/* Standard mode read-only remounts - preserves paths, blocks writes.
 * Covers both sensitive proc subtrees and dangerous sys interfaces. */
static const char *standard_ro[] = {
  "/proc/irq",
  "/sys/firmware",
  "/sys/kernel/security",
  "/sys/kernel/debug",
  "/sys/kernel/tracing",
  "/sys/block",
  nullptr
};

/* /proc/sys/net intentionally excluded: in host mode it's a
 * destructive host network modification channel.  In isolated
 * (none) mode there is no network, so writable net sysctls
 * are unnecessary. */
static const char *rw_holes[] = {
  "/proc/sys/kernel/hostname",
  "/proc/sys/kernel/domainname",
  nullptr
};

/* Mask a sensitive path by self-binding and remounting read-only.
 * Silently skips if the path doesn't exist.  The resulting mount entry
 * preserves the parent filesystem type (e.g. "proc on /proc/kcore type
 * proc (ro)") - matching LXC's clean approach. */
static void mask_path(const char *path) {
  if (access(path, F_OK) != 0)
    return;
  mount(path, path, nullptr, MS_BIND, nullptr);
  mount(path, path, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
}

/* Nullify a sensitive path by bind-mounting /dev/null over it.
 * Silently skips if either path doesn't exist.  Used for kernel log
 * interfaces (/proc/kmsg) where read access itself must be blocked,
 * not just writes.  Matches the approach used by LXC.
 *
 * NOTE: For paths that cause CPU-spin when read returns EOF (e.g. rsyslogd
 * imklog), use kmsg_block_read() instead — it provides a FIFO that blocks
 * readers indefinitely, preventing the tight read-EOF-retry loop. */
static void nullify_path(const char *path) {
  if (access(path, F_OK) != 0)
    return;
  if (access("/dev/null", F_OK) != 0)
    return;
  mount("/dev/null", path, nullptr, MS_BIND, nullptr);
}

/* Block a path with a FIFO that has a persistent writer.
 * Readers block on read() instead of getting immediate EOF — this prevents
 * CPU-spin in daemons like rsyslogd imklog that retry in a tight loop.
 * The writer child holds the FIFO open until the container dies. */
static void block_read_path(const char *path) {
  if (access(path, F_OK) != 0)
    return;

  char fifo_path[64];
  snprintf(fifo_path, sizeof(fifo_path), "/tmp/." PROJECT_NAME "-kmsg-fifo-%d",
           getpid());

  unlink(fifo_path);
  if (mkfifo(fifo_path, 0600) < 0)
    return;

  /* Fork a child to hold the FIFO write end open; otherwise readers get
   * immediate EOF (or ENXIO with O_NONBLOCK).  The child does nothing — it
   * just exists to keep the write end alive. */
  const pid_t child = fork();
  if (child == 0) {
    const int wfd = open(fifo_path, O_WRONLY);
    if (wfd >= 0)
      pause();
    _exit(0);
  }

  /* Bind-mount the FIFO over the target path.  Readers will block awaiting
   * data that never arrives — no CPU spin. */
  if (child > 0)
    mount(fifo_path, path, nullptr, MS_BIND, nullptr);

  unlink(fifo_path);
}

/*
 * apply_jail_mask()
 *
 * Secure sensitive kernel interfaces by self-binding and remounting them
 * read-only.  This reduces the container's attack surface and prevents it
 * from manipulating the host kernel via /proc and /sys.
 *
 * In Standard Mode (hw_access=0), we are very strict.
 * In Hardware Mode (hw_access=1), we preserve most paths to fulfill the
 * "everything possible" requirement for low-level hardware tools.
 */
void apply_jail_mask(const bool hw_access, const int privileged_mask) {
  if (privileged_mask & PRIV_NOMASK) {
    log_info(
        "[SEC] --privileged=nomask: skipping jail masks for /proc and /sys.");
    return;
  }

  /* Apply universal masks */
  for (int i = 0; universal_masks[i]; i++) {
    mask_path(universal_masks[i]);
  }

  /* Apply universal nullify (bind-mount /dev/null over sensitive paths) */
  for (int i = 0; universal_nullify[i]; i++) {
    nullify_path(universal_nullify[i]);
  }

  /* Block kernel log reads with FIFO to prevent CPU-spin (rsyslogd imklog) */
  for (int i = 0; kmsg_block_paths[i]; i++) {
    block_read_path(kmsg_block_paths[i]);
  }

  /* Universal: mask all cgroup v1 release_agent files.
   *
   * In --force-cgroupv1 mode, host cgroup v1 hierarchies are bind-mounted
   * into the container. release_agent files are writable by root and the
   * kernel executes them AS REAL HOST ROOT, outside all namespaces, when the
   * last process leaves a cgroup (notify_on_release=1). This is the
   * CVE-2022-0492 class of escape - confirmed exploitable in testing.
   *
   * Self-bind + RO remount makes them unwritable while leaving the rest of
   * the cgroup hierarchy fully functional. */
  {
    auto_closedir DIR *cgdir = opendir("/sys/fs/cgroup");
    if (cgdir) {
      struct dirent *de;
      while ((de = readdir(cgdir)) != nullptr) {
        if (de->d_name[0] == '.')
          continue;
        char agent_path[PATH_MAX];
        snprintf(agent_path, sizeof(agent_path),
                 "/sys/fs/cgroup/%s/release_agent", de->d_name);
        mask_path(agent_path);
      }
    }
  }

  /*
   * Wholesale /proc/sys lockdown - applied in BOTH standard and hardware mode.
   *
   * /proc/sys reflects the host kernel's sysctl state and is NOT scoped to the
   * PID namespace. Even with a fresh procfs, a container running as root can
   * write to /proc/sys/kernel/unprivileged_bpf_disabled, /proc/sys/fs/, etc.
   * and corrupt Android host state (eBPF subsystem, dmesg, perf, hardlinks).
   *
   * Strategy: punch RW bind-mounts for the UTS-namespace-scoped
   * subtrees FIRST, then lock all of /proc/sys read-only.
   * The pre-existing submounts shadow the parent remount.
   *
   * RW holes (UTS-namespace scoped — safe for containers to write):
   *   /proc/sys/kernel/hostname   - UTS-namespace scoped
   *   /proc/sys/kernel/domainname - UTS-namespace scoped
   *
   * Everything else is blocked: kernel/, vm/, fs/, dev/, abi/, debug/.
   * This covers all the dangerous sysctls in one mount entry instead of
   * playing whack-a-mole with individual paths.
   */
  {
    /* Step 1: Lock all of /proc/sys RO via self-bind + remount.
     * Must happen BEFORE pinning RW holes - once the parent is RO, new
     * bind mounts stacked on top of it can be independently RW. */
    if (access("/proc/sys", F_OK) == 0) {
      mount("/proc/sys", "/proc/sys", nullptr, MS_BIND, nullptr);
      mount("/proc/sys", "/proc/sys", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY,
            nullptr);
      log_info("[SEC] /proc/sys locked RO.");
    }

    /* Step 2: Stack RW bind mounts on top of the now-RO /proc/sys.
     * Bind inherits RO from parent, so explicitly remount RW after. */
    for (int i = 0; rw_holes[i]; i++) {
      if (access(rw_holes[i], F_OK) != 0)
        continue;
      if (mount(rw_holes[i], rw_holes[i], nullptr, MS_BIND, nullptr) < 0) {
        log_warn("[SEC] Failed to bind RW hole %s: %s", rw_holes[i],
                 strerror(errno));
        continue;
      }
      if (mount(rw_holes[i], rw_holes[i], nullptr,
                MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                nullptr) < 0)
        log_warn("[SEC] Failed to remount RW hole %s: %s", rw_holes[i],
                 strerror(errno));
    }
    log_info("[SEC] /proc/sys RW holes preserved (hostname/domainname).");
  }

  if (hw_access) {
    log_info("[SEC] Hardware Mode: preserved sensitive /proc and /sys paths.");
    return;
  }

  /* Apply standard mode read-only remounts */
  for (int i = 0; standard_ro[i]; i++) {
    mask_path(standard_ro[i]);
  }

  log_info("[SEC] Jail mask applied (hardened /proc and /sys).");
}
