/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ds-fork.h"

/**
 * Ported LXC-style Cgroup Setup:
 * 1. Discover host hierarchies from /proc/self/mountinfo.
 * 2. If Cgroup Namespace is active (Linux 4.6+), mount hierarchies directly.
 * 3. Otherwise (Legacy), bind-mount the container's subset from the host.
 */

/* Scan mountinfo for any host cgroup2 mount (e.g. /dev/cg2_bpf on Android).
 * Returns 1 and fills 'buf' if found. */
static int find_host_cgroup2_mount(char *buf, size_t size) {
  FILE *f = fopen("/proc/self/mountinfo", "re");
  if (!f)
    return 0;

  char line[2048];
  int found = 0;
  while (fgets(line, sizeof(line), f)) {
    char *dash = strstr(line, " - ");
    if (!dash)
      continue;
    char fstype[16];
    if (sscanf(dash + 3, "%15s", fstype) != 1)
      continue;
    if (strcmp(fstype, "cgroup2") != 0)
      continue;

    /* Extract mountpoint (field 5) */
    char *p = line;
    for (int i = 0; i < 4; i++) {
      p = strchr(p, ' ');
      if (!p)
        break;
      p++;
    }
    if (!p)
      continue;
    char *mp_end = strchr(p, ' ');
    if (!mp_end)
      continue;
    *mp_end = '\0';

    /* Skip ds-fork-internal mounts to avoid false positives on restart */
    if (strstr(p, "/" PROJECT_NAME "/"))
      continue;

    if (buf)
      safe_strncpy(buf, p, size);
    found = 1;
    break;
  }
  fclose(f);
  return found;
}

/* Scans mountinfo to find any cgroup2 mount - covers /dev/cg2_bpf (Android)
 * and /sys/fs/cgroup placed by cgroup_host_bootstrap(). */
int cgroup_host_is_v2(void) { return find_host_cgroup2_mount(NULL, 0); }

/* Returns 1 if the kernel supports cgroup2 (check /proc/filesystems). */
int cgroup_kernel_supports_v2(void) {
  return (grep_file("/proc/filesystems", "cgroup2") > 0);
}

/* Mount cgroup2 on /sys/fs/cgroup if the host hasn't done so.
 * Android recovery kernels support cgroup2 but only mount it at /dev/cg2_bpf;
 * systemd needs it at /sys/fs/cgroup. Sequence: mkdir -> tmpfs anchor ->
 * cgroup2. */
void cgroup_host_bootstrap(int force_cgroupv1) {
  if (force_cgroupv1)
    return;

  /* Already done */
  struct statfs sfs;
  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      (unsigned long)sfs.f_type == (unsigned long)CGROUP2_SUPER_MAGIC)
    return;

  /* No probe_cgroup2_mount(): mkdtemp fails on ramfs roots (no /tmp).
   * The mount() calls below self-report failure via errno. */
  if (grep_file("/proc/filesystems", "cgroup2") <= 0) {
    log_info("[CGROUP] cgroup2 not in /proc/filesystems, skipping bootstrap.");
    return;
  }

  if (access("/sys/fs/cgroup", F_OK) != 0) {
    if (mkdir_p("/sys/fs/cgroup", 0755) != 0) {
      log_error("[CGROUP] Failed to create /sys/fs/cgroup: %s",
                strerror(errno));
      return;
    }
  }

  /* tmpfs anchor needed: cgroup2 can't layer directly on ramfs */
  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      (unsigned long)sfs.f_type != (unsigned long)TMPFS_MAGIC &&
      (unsigned long)sfs.f_type != (unsigned long)CGROUP2_SUPER_MAGIC) {
    if (mount("none", "/sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") != 0) {
      log_error("[CGROUP] Failed to mount tmpfs on /sys/fs/cgroup: %s",
                strerror(errno));
      return;
    }
    log_info("[CGROUP] Mounted tmpfs anchor on /sys/fs/cgroup.");
  }

  if (mount("none", "/sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
    log_error("Failed to mount cgroup2 on /sys/fs/cgroup: %s", strerror(errno));
    return;
  }
  log_info("Auto-mounted cgroup2 on /sys/fs/cgroup.");
}

/*
 * mount_v1_controllers - unified v1 controller setup, works on every host.
 *
 * Iterates /proc/cgroups (kernel truth) for every enabled controller.
 * For each one:
 *   1. If already present in sys/fs/cgroup/ -> skip (idempotent).
 *   2. If found in the host map AND in_ns  -> fresh namespace mount.
 *   3. If found in the host map, no ns     -> bind-mount from host path.
 *   4. Not in map (pure-v2, hybrid gap)    -> synthesize a fresh v1 mount.
 *      This is safe: the kernel accepts a fresh v1 mount for any subsystem
 *      that isn't already bound to an active v2 hierarchy with live tasks.
 *
 * Co-mounted hierarchies (e.g. net_cls,net_prio on the same host mount)
 * get symlinks for their secondary names, matching historical behaviour.
 */
static void mount_v1_controllers(void) {
  FILE *f = fopen("/proc/cgroups", "re");
  if (!f)
    return;

  unsigned long flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
  char line[256];
  if (!fgets(line, sizeof(line), f)) { /* skip header */
    fclose(f);
    return;
  }

  while (fgets(line, sizeof(line), f)) {
    char name[64];
    int hier, ncg, enabled;
    if (sscanf(line, "%63s %d %d %d", name, &hier, &ncg, &enabled) != 4)
      continue;
    if (!enabled)
      continue;

    char mp[PATH_MAX];
    snprintf(mp, sizeof(mp), "sys/fs/cgroup/%s", name);
    if (access(mp, F_OK) == 0)
      continue; /* already set up or co-mounted */

    if (mkdir(mp, 0755) < 0 && errno != EEXIST)
      continue;

    /* Always synthesize a fresh v1 mount for every subsystem.
     * The kernel translates this to the container's isolated cgroupns root. */
    if (mount("cgroup", mp, "cgroup", flags, name) != 0) {
      log_info("[CGROUP] v1 controller '%s' unavailable: %s", name,
               strerror(errno));
      rmdir(mp);
    } else {
      log_info("[CGROUP] v1 mounted: %s", name);
    }
  }
  fclose(f);
}

int setup_cgroups(int force_cgroupv1) {
  cgroup_host_bootstrap(force_cgroupv1);

  if (access("sys/fs/cgroup", F_OK) != 0) {
    if (mkdir_p("sys/fs/cgroup", 0755) < 0)
      return -1;
  }

  /* Mount tmpfs as the cgroup base */
  if (domount("none", "sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") < 0)
    return -1;

  int v2_active = cgroup_host_is_v2() && !force_cgroupv1;
  int systemd_setup_done = 0;

  if (v2_active) {
    /* Always mount a fresh cgroup2 hierarchy within the container's
     * cgroup namespace. Isolation is handled by the kernel namespace. */
    if (mount("cgroup2", "sys/fs/cgroup", "cgroup2",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0) {
      systemd_setup_done = 1;
    } else {
      log_error("Failed to mount cgroup2: %s", strerror(errno));
    }
  } else {
    /* V1 PATH (force_cgroupv1): Synthesize fresh mounts for all controllers. */
    mount_v1_controllers();
    systemd_setup_done = 1; /* handled via systemd named cgroup below */
  }

  /* Ensure a systemd cgroup hierarchy exists for systemd containers.
   * On v1 this is a named cgroup; on v2 systemd uses the unified root. */
  if (!v2_active) {
    if (access("sys/fs/cgroup/systemd", F_OK) != 0) {
      mkdir("sys/fs/cgroup/systemd", 0755);
      if (mount("cgroup", "sys/fs/cgroup/systemd", "cgroup",
                MS_NOSUID | MS_NODEV | MS_NOEXEC, "none,name=systemd") < 0) {
        log_error("Failed to mount systemd cgroup: %s", strerror(errno));
        return -1;
      }
    }
    systemd_setup_done = 1;
  }

  if (!systemd_setup_done) {
    log_error("Systemd cgroup setup failed. Systemd containers cannot boot.");
    return -1;
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * cgroup_cleanup_container
 *
 * Removes the entire /sys/fs/cgroup/ds-fork/<container_name>/ subtree
 * that was created at container start for cgroup namespace isolation.
 *
 * The kernel requires a bottom-up rmdir walk - a cgroup directory can only
 * be removed after all its children are gone.  All container processes are
 * dead by the time cleanup_container_resources() calls this, so every leaf
 * is empty and the walk always succeeds.
 *
 * Safe to call on every stop regardless of whether the directory exists
 * (all rmdir calls are silently ignored on ENOENT).
 * ---------------------------------------------------------------------------*/

/* Recursive bottom-up rmdir of a cgroup subtree.  cgroup directories can
 * only be removed from the leaves upward - attempting to rmdir a non-empty
 * cgroup returns EBUSY.
 *
 * Even after all processes exit, cgroup state is destroyed asynchronously
 * by the kernel.  Child dirs enter a "dying" state that is invisible to
 * readdir() but still causes the parent's rmdir() to return EBUSY.
 *
 * We handle this with two mechanisms:
 *   1. cgroup.kill (kernel 5.14+): write "1" to kill all remaining
 *      processes in the subtree atomically, then poll cgroup.events
 *      until populated=0 before attempting rmdir.
 *   2. Retry loop: for older kernels without cgroup.kill, retry rmdir
 *      with short sleeps to let the async cleanup complete. */
static void rmdir_cgroup_tree(const char *path) {
  DIR *d = opendir(path);
  if (!d) {
    rmdir(path);
    return;
  }

  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.')
      continue;
    if (de->d_type != DT_DIR)
      continue;

    char child[PATH_MAX];
    safe_strncpy(child, path, sizeof(child));
    strncat(child, "/", sizeof(child) - strlen(child) - 1);
    strncat(child, de->d_name, sizeof(child) - strlen(child) - 1);
    rmdir_cgroup_tree(child);
  }
  closedir(d);

  /* 1. cgroup.kill - available on kernel 5.14+.
   *    Writing "1" sends SIGKILL to every process in the subtree
   *    atomically, including those in dying child cgroups. */
  char kill_path[PATH_MAX];
  safe_strncpy(kill_path, path, sizeof(kill_path));
  strncat(kill_path, "/cgroup.kill", sizeof(kill_path) - strlen(kill_path) - 1);
  if (access(kill_path, W_OK) == 0) {
    int kfd = open(kill_path, O_WRONLY | O_CLOEXEC);
    if (kfd >= 0) {
      if (write(kfd, "1", 1) < 0) {
      }
      close(kfd);
    }
  }

  /* 2. Poll cgroup.events for populated=0.
   *    Bail out after ~500ms (50 × 10ms) to avoid blocking forever. */
  char events_path[PATH_MAX];
  safe_strncpy(events_path, path, sizeof(events_path));
  strncat(events_path, "/cgroup.events",
          sizeof(events_path) - strlen(events_path) - 1);
  for (int i = 0; i < 50; i++) {
    char buf[256] = {0};
    if (read_file(events_path, buf, sizeof(buf)) > 0) {
      if (strstr(buf, "populated 0"))
        break;
    }
    usleep(10000); /* 10 ms */
  }

  /* 3. rmdir with retry - handles residual dying descendants on older
   *    kernels that lack cgroup.kill.  10 attempts × 20 ms = 200 ms max. */
  for (int attempt = 0; attempt < 10; attempt++) {
    if (rmdir(path) == 0 || errno == ENOENT)
      return;
    if (errno != EBUSY)
      return;      /* unexpected error - give up */
    usleep(20000); /* 20 ms */
  }
}

void cgroup_cleanup_container(const char *container_name) {
  if (!container_name || !container_name[0])
    return;

  char safe_name[256];
  sanitize_container_name(container_name, safe_name, sizeof(safe_name));

  DIR *d = opendir("/sys/fs/cgroup");
  if (!d)
    return;

  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.')
      continue;

    char cg_path[PATH_MAX];
    snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/%s/" PROJECT_NAME "/%s",
             de->d_name, safe_name);

    /* Handle unified V2 where ds-fork/ is at root */
    if (strcmp(de->d_name, "cgroup.procs") == 0)
      snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/" PROJECT_NAME "/%s",
               safe_name);

    if (access(cg_path, F_OK) != 0)
      continue;
    rmdir_cgroup_tree(cg_path);
    if (strcmp(de->d_name, "cgroup.procs") == 0)
      break;
  }
  closedir(d);
}

static int host_supports_v2_cached = -1;

void print_cgroup_status(struct config *cfg) {
  int limits_set = (cfg->memory_limit || cfg->cpu_quota || cfg->pids_limit);

  if (cfg->force_cgroupv1) {
    log_warn("Using legacy Cgroup V1 hierarchy (forced by --force-cgroupv1)");
    if (limits_set) {
      log_warn("Resource limits (--memory/--cpus/--pids-limit) require "
               "cgroup v2 and will not be applied for this container.");
    }
    return;
  }

  if (host_supports_v2_cached == -1)
    host_supports_v2_cached = cgroup_kernel_supports_v2();

  if (!host_supports_v2_cached) {
    log_warn("Host does not support Cgroup V2 (falling back to legacy V1)");
    if (limits_set) {
      log_warn(
          "[CGROUP] Resource limits (--memory/--cpus/--pids-limit) require "
          "cgroup v2 and will not be applied on this host.");
    }
  }
}

/* Returns 1 if 'name' appears in a space/newline-separated controller list. */
static int ctrl_in_list(const char *list, const char *name) {
  const char *p = list;
  size_t nlen = strlen(name);
  while (*p) {
    while (*p == ' ' || *p == '\n')
      p++;
    if (strncmp(p, name, nlen) == 0 &&
        (p[nlen] == ' ' || p[nlen] == '\n' || p[nlen] == '\0'))
      return 1;
    while (*p && *p != ' ' && *p != '\n')
      p++;
  }
  return 0;
}

/* Public wrapper for cross-TU use (e.g. container.c). */
int cg_word_in_list(const char *list, const char *name) {
  return ctrl_in_list(list, name);
}

/* Check controller availability before touching any cgroup files. */
static int ctrl_supported_v2(const char *cg_path, const char *name) {
  if (strlen(cg_path) > PATH_MAX - 32)
    return 0;
  char buf[256];
  char path[PATH_MAX + 64];
  snprintf(path, sizeof(path), "%s/cgroup.controllers", cg_path);
  if (read_file(path, buf, sizeof(buf)) <= 0)
    return 0;
  return ctrl_in_list(buf, name);
}

/* Helper: parse a cgroup integer file that may contain "max" (unlimited).
 * Returns the parsed value, or -1 on error/unlimited. */
static long long parse_cgroup_ll(const char *buf) {
  if (strncmp(buf, "max", 3) == 0)
    return -1; /* unlimited */
  char *end;
  errno = 0;
  long long v = strtoll(buf, &end, 10);
  if (errno || end == buf)
    return -1;
  return v;
}

int cgroup_apply_limits(struct config *cfg) {
  if (!cfg->memory_limit && !cfg->cpu_quota && !cfg->pids_limit)
    return 0;

  /* Resource limits require cgroup v2. v1 hierarchies are often pre-claimed
   * by the host systemd and cannot be reliably delegated. Skip with a
   * warning when --force-cgroupv1 is active or the host has no v2 mount. */
  if (cfg->force_cgroupv1 || !cgroup_host_is_v2()) {
    cfg->memory_limit = 0;
    cfg->cpu_quota = 0;
    cfg->pids_limit = 0;
    return 0;
  }

  char safe_name[256];
  sanitize_container_name(cfg->container_name, safe_name, sizeof(safe_name));

  char cg[PATH_MAX - 64];
  char path[PATH_MAX + 64], val[64];
  int err = 0;

  snprintf(cg, sizeof(cg), "/sys/fs/cgroup/" PROJECT_NAME "/%s", safe_name);
  if (access(cg, F_OK) != 0) {
    log_warn("[CGROUP] Container cgroup not found, limits skipped.");
    return -1;
  }
  /* Check the delegated cgroup's controllers, not the root. Controllers
   * must be enabled in subtree_control of each parent to be usable here. */
  if (cfg->memory_limit) {
    if (ctrl_supported_v2(cg, "memory")) {
      snprintf(path, sizeof(path), "%s/memory.max", cg);
      snprintf(val, sizeof(val), "%lld", cfg->memory_limit);
      if (write_file(path, val) < 0) {
        log_warn("[CGROUP] memory.max: %s", strerror(errno));
        cfg->memory_limit = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 'memory' controller not supported, limit skipped.");
      cfg->memory_limit = 0;
    }
  }
  if (cfg->cpu_quota) {
    if (ctrl_supported_v2(cg, "cpu")) {
      long long period = cfg->cpu_period > 0 ? cfg->cpu_period : 100000;
      snprintf(path, sizeof(path), "%s/cpu.max", cg);
      snprintf(val, sizeof(val), "%lld %lld", cfg->cpu_quota, period);
      if (write_file(path, val) < 0) {
        log_warn("[CGROUP] cpu.max: %s", strerror(errno));
        cfg->cpu_quota = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 'cpu' controller not supported, limit skipped.");
      cfg->cpu_quota = 0;
    }
  }
  if (cfg->pids_limit) {
    if (ctrl_supported_v2(cg, "pids")) {
      snprintf(path, sizeof(path), "%s/pids.max", cg);
      snprintf(val, sizeof(val), "%lld", cfg->pids_limit);
      if (write_file(path, val) < 0) {
        log_warn("[CGROUP] pids.max: %s", strerror(errno));
        cfg->pids_limit = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 'pids' controller not supported, limit skipped.");
      cfg->pids_limit = 0;
    }
  }
  return err ? -1 : 0;
}

int cgroup_get_usage(struct config *cfg, long long *mem, long long *cpu_us,
                     long long *pids) {
  if (mem)
    *mem = -1;
  if (cpu_us)
    *cpu_us = -1;
  if (pids)
    *pids = -1;

  char safe_name[256];
  sanitize_container_name(cfg->container_name, safe_name, sizeof(safe_name));

  int v2 = cgroup_host_is_v2();
  /* Keep cg strictly within PATH_MAX-64 so the suffix appended
   * into path never overflows the PATH_MAX+64 path buffer. */
  char cg[PATH_MAX - 64];
  char path[PATH_MAX + 64], buf[256];

  if (v2) {
    snprintf(cg, sizeof(cg), "/sys/fs/cgroup/" PROJECT_NAME "/%s", safe_name);
    if (access(cg, F_OK) != 0)
      return -1;
    /* Use parse_cgroup_ll() so that "max" (= unlimited/not set)
     * is reported as -1 rather than silently becoming 0. */
    if (mem) {
      snprintf(path, sizeof(path), "%s/memory.current", cg);
      if (read_file(path, buf, sizeof(buf)) > 0)
        *mem = parse_cgroup_ll(buf);
    }
    if (cpu_us) {
      snprintf(path, sizeof(path), "%s/cpu.stat", cg);
      if (read_file(path, buf, sizeof(buf)) > 0) {
        char *p = strstr(buf, "usage_usec ");
        if (p)
          *cpu_us = parse_cgroup_ll(p + 11);
      }
    }
    if (pids) {
      snprintf(path, sizeof(path), "%s/pids.current", cg);
      if (read_file(path, buf, sizeof(buf)) > 0)
        *pids = parse_cgroup_ll(buf);
    }
  }
  return 0;
}
