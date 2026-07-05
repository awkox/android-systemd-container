/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* ---------------------------------------------------------------------------
 * String helpers
 * ---------------------------------------------------------------------------*/

bool is_ramfs(const char *path) {
  struct statfs sfs;
  if (statfs(path, &sfs) < 0)
    return false;
  return sfs.f_type == RAMFS_MAGIC || sfs.f_type == TMPFS_MAGIC;
}

/* ---------------------------------------------------------------------------
 * UUID generation  - 32 hex chars from /dev/urandom
 * ---------------------------------------------------------------------------*/

int generate_uuid(char *buf, size_t size) {
  if (!buf || size < UUID_LEN + 1)
    return -1;

  unsigned char raw[UUID_LEN / 2];

  /* Primary path: /dev/urandom */
  auto_close int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t r = read(fd, raw, sizeof(raw));

    if (r == (ssize_t)sizeof(raw)) {
      for (int i = 0; i < (int)sizeof(raw); i++)
        snprintf(buf + i * 2, 3, "%02x", raw[i]);

      buf[UUID_LEN] = '\0';
      return 0;
    }
  }

  /* Fallback path: seeded rand() */
  static bool seeded = false;
  if (!seeded) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    unsigned int seed =
        (unsigned int)(ts.tv_nsec ^ ts.tv_sec ^ getpid() ^ getppid());

    srand(seed);
    seeded = true;
  }

  for (int i = 0; i < UUID_LEN / 2; i++)
    raw[i] = (unsigned char)(rand() & 0xFF);

  for (int i = 0; i < (int)sizeof(raw); i++)
    snprintf(buf + i * 2, 3, "%02x", raw[i]);

  buf[UUID_LEN] = '\0';
  return 0;
}

/* ---------------------------------------------------------------------------
 * /proc path helpers
 * ---------------------------------------------------------------------------*/

int parse_os_release(const char *rootfs_path, char *id_out, char *ver_out,
                     size_t out_size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%.4000s" OS_RELEASE, rootfs_path);

  char buf[4096];
  if (read_file(path, buf, sizeof(buf)) < 0)
    return -1;

  /* Default values */
  safe_strncpy(id_out, "linux", out_size);
  if (ver_out)
    ver_out[0] = '\0';

  /* Parse ID */
  char *p = strstr(buf, "\nID=");
  if (!p && strncmp(buf, "ID=", 3) == 0)
    p = buf;

  if (p) {
    if (*p == '\n')
      p++;
    p += 3;
    if (*p == '"')
      p++;
    int i = 0;
    while (p[i] && p[i] != '"' && p[i] != '\n' && (size_t)i < out_size - 1) {
      id_out[i] = p[i];
      i++;
    }
    id_out[i] = '\0';
  }

  /* Parse VERSION_ID */
  if (ver_out) {
    p = strstr(buf, "VERSION_ID=");
    if (p) {
      p += 11;
      if (*p == '"')
        p++;
      int i = 0;
      while (p[i] && p[i] != '"' && p[i] != '\n' && (size_t)i < out_size - 1) {
        ver_out[i] = p[i];
        i++;
      }
      ver_out[i] = '\0';
    }
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * /proc/<pid>/environ reader
 * ---------------------------------------------------------------------------*/

int read_proc_environ(pid_t pid, const char *key, char *value, size_t size) {
  if (!key || !value || size == 0 || pid <= 0)
    return -1;

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/environ", pid);

  auto_fclose FILE *f = fopen(path, "re");
  if (!f)
    return -1;

  int keylen = strlen(key);
  int found = -1;

  while (1) {
    int c = fgetc(f);
    if (c == EOF)
      break;

    if (c == key[0]) {
      long pos = ftell(f);
      if (pos < 0)
        break;
      fseek(f, pos - 1, SEEK_SET);

      bool matched = true;
      for (int i = 0; i < keylen; i++) {
        int kc = fgetc(f);
        if (kc != (unsigned char)key[i]) {
          matched = false;
          break;
        }
      }
      if (matched && fgetc(f) == '=') {
        int vi = 0;
        while (vi < (int)size - 1) {
          int vc = fgetc(f);
          if (vc == EOF || vc == '\0')
            break;
          value[vi++] = (char)vc;
        }
        value[vi] = '\0';
        found = 0;
        break;
      }
    }

    while ((c = fgetc(f)) != EOF && c != '\0')
      ;
  }

  return found;
}

/* ---------------------------------------------------------------------------
 * Safe /proc/<pid>/root open — prevents symlink traversal at ALL path levels.
 *
 * open("/proc/<pid>/root/sub/dir/file", O_NOFOLLOW) only protects the FINAL
 * component.  A symlink at "sub", "dir", or any intermediate component is
 * silently followed by the kernel.  This walks each component with
 * openat(O_NOFOLLOW), failing if any intermediate path is a symlink.
 * ---------------------------------------------------------------------------*/

int safe_openat_proc(pid_t pid, const char *subpath, int flags, mode_t mode) {
  if (pid <= 0 || !subpath || subpath[0] == '\0')
    return -1;

  /* Enter the container's root.  /proc/<pid>/root is a magic symlink that
   * MUST be followed (O_NOFOLLOW would fail on it). */
  char root[64];
  snprintf(root, sizeof(root), "/proc/%d/root", pid);
  auto_close int dirfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0)
    return -1;

  /* Walk each component with O_NOFOLLOW.  A copy is needed because strtok
   * modifies the string. */
  char tmp[PATH_MAX];
  safe_strncpy(tmp, subpath, sizeof(tmp));

  char *save = nullptr;
  char *comp = strtok_r(tmp, "/", &save);
  char *next = strtok_r(nullptr, "/", &save);

  while (comp && next) {
    int nextfd =
        openat(dirfd, comp, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    close(dirfd);
    if (nextfd < 0)
      return -1;
    dirfd = nextfd;
    comp = next;
    next = strtok_r(nullptr, "/", &save);
  }

  /* Open the final component with the caller's flags + O_NOFOLLOW */
  int fd = -1;
  if (comp)
    fd = openat(dirfd, comp, flags | O_NOFOLLOW | O_CLOEXEC, mode);

  return fd;
}

/* ---------------------------------------------------------------------------
 * Kernel firmware search path management
 *
 * Android kernels patch firmware_class.c to support a comma-separated list
 * of custom search paths in the single 256-byte fw_path_para buffer
 * (e.g. "/vendor/firmware,/efs/wifi").  Writing a newline to the sysfs node
 * pops the first entry but always preserves the tail - so the last path can
 * never be fully cleared.  We therefore never attempt a full clear; removal
 * is best-effort and skipped when it would leave an empty string.
 *
 * Only called when --hw-access is active AND /lib/firmware exists in the
 * rootfs - both conditions are enforced at every call site.
 * Not supported on desktop Linux - both functions are no-ops there.
 * ---------------------------------------------------------------------------*/

/* Android kernel fw_path_para is 256 bytes including the NUL terminator. */
#define FW_PATH_BUF_SIZE 256

/*
 * Token-aware removal: walk the comma-separated list and rebuild it without
 * the matching entry.  Matches on exact token boundaries (not substrings) to
 * avoid accidentally removing "/tmp/" PROJECT_NAME "/mnt/Void" when removing
 * "/tmp/" PROJECT_NAME "/mnt/Void2".
 * Returns the length of the rebuilt string (0 = only entry, do not write).
 */
static int fw_remove_token(const char *buf, const char *token, char *out,
                           size_t out_size) {
  size_t token_len = strlen(token);
  const char *p = buf;
  bool first = true;
  out[0] = '\0';

  while (*p) {
    const char *comma = strchr(p, ',');
    size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);

    if (!(seg_len == token_len && memcmp(p, token, token_len) == 0)) {
      /* Not our token - keep it */
      if (!first)
        strncat(out, ",", out_size - strlen(out) - 1);
      strncat(out, p,
              (seg_len < out_size - strlen(out) - 1)
                  ? seg_len
                  : out_size - strlen(out) - 1);
      first = false;
    }

    if (!comma)
      break;
    p = comma + 1;
  }

  return (int)strlen(out);
}

void firmware_path_add(const char *fw_path) {
  /* Bail silently if /lib/firmware is absent in the rootfs. */
  struct stat st;
  if (stat(fw_path, &st) < 0)
    return;

  /* Read the current comma-separated path list.
   * read_file() already strips trailing newlines. */
  char current[FW_PATH_BUF_SIZE] = {0};
  read_file(FW_PATH_FILE, current, sizeof(current));

  /* Idempotent - don't add if already present as an exact token. */
  size_t fw_len = strlen(fw_path);
  const char *p = current;
  while (*p) {
    const char *comma = strchr(p, ',');
    size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);
    if (seg_len == fw_len && memcmp(p, fw_path, fw_len) == 0)
      return; /* already there */
    if (!comma)
      break;
    p = comma + 1;
  }

  /* Build "fw_path,existing" - prepend so container firmware wins over OEM
   * defaults.  Guard against the 255-char string limit of fw_path_para.
   * Pre-validate lengths so the compiler can confirm no truncation occurs. */
  char new_path[FW_PATH_BUF_SIZE] = {0};
  if (current[0]) {
    size_t needed =
        strlen(fw_path) + 1 /* comma */ + strlen(current) + 1 /* NUL */;
    if (needed > sizeof(new_path)) {
      log_warn("[FW] firmware path too long to prepend '%s' - skipping",
               fw_path);
      return;
    }
    /* Lengths validated - safe to build without truncation. */
    safe_strncpy(new_path, fw_path, sizeof(new_path));
    strncat(new_path, ",", sizeof(new_path) - strlen(new_path) - 1);
    strncat(new_path, current, sizeof(new_path) - strlen(new_path) - 1);
  } else {
    safe_strncpy(new_path, fw_path, sizeof(new_path));
  }

  log_info("[FW] Adding firmware path: %s", fw_path);
  write_file(FW_PATH_FILE, new_path);
}

void firmware_path_remove(const char *fw_path) {
  /* Read current list - read_file() strips trailing newlines. */
  char current[FW_PATH_BUF_SIZE] = {0};
  if (read_file(FW_PATH_FILE, current, sizeof(current)) < 0)
    return;

  char new_path[FW_PATH_BUF_SIZE] = {0};
  int new_len = fw_remove_token(current, fw_path, new_path, sizeof(new_path));

  if (new_len == 0) {
    /* Our path was the only entry.  The Android kernel never allows a full
     * clear - writing empty would be a no-op anyway - so just leave it. */
    log_info("[FW] Skipping firmware path removal (last entry): %s", fw_path);
    return;
  }

  log_info("[FW] Removing firmware path: %s", fw_path);
  write_file(FW_PATH_FILE, new_path);
}

/* ---------------------------------------------------------------------------
 * Safe Command Execution (fork + execvp)
 * ---------------------------------------------------------------------------*/

static int internal_run(char *const argv[], bool quiet) {
  pid_t pid = fork();
  if (pid < 0)
    return -1;

  if (pid == 0) {
    if (quiet) {
      auto_close int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 1);
        dup2(devnull, 2);
      }
    }
    execvp(argv[0], argv);
    _exit(127); /* exec failed */
  }

  int status;
  if (waitpid(pid, &status, 0) < 0)
    return -1;

  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  return -1;
}

int run_command_quiet(char *const argv[]) { return internal_run(argv, true); }

/* ---------------------------------------------------------------------------
 * System helpers
 * ---------------------------------------------------------------------------*/

int get_kernel_version(int *major, int *minor) {
  struct utsname uts;
  if (uname(&uts) < 0)
    return -1;

  if (sscanf(uts.release, "%d.%d", major, minor) != 2)
    return -1;

  return 0;
}

/* ---------------------------------------------------------------------------
 * show_container_usage
 *
 * Prints uptime, CPU%, and RAM usage for a running container.
 * Works entirely from the host side - no namespace entry required.
 * Compatible with kernel 3.10+.
 *
 * Method:
 *   UPTIME  - field 22 (starttime) of /proc/<init_pid>/stat converted to
 *             seconds, subtracted from /proc/uptime.
 *   MEMORY  - PID namespace walk: any PID whose ns/pid matches container
 *             init's namespace is in the container. Sum VmRSS.
 *   CPU     - same walk, sum utime+stime jiffies, two samples 1s apart.
 *             Divide delta by host CPU delta for percentage.
 *             Per-mille avoids integer floor on sub-1% values.
 *
 *   OPTIMISATION: walk 1 collects RAM + CPU sample 1 simultaneously.
 *   walk 2 (after sleep) collects CPU sample 2 only. Total: 2 walks.
 *
 * Output (machine-parseable key=value):
 *   UPTIME_SEC=<seconds>
 *   UPTIME=<Xd Xh Xm Xs | Xh Xm Xs>
 *   RAM_USED_KB=<kb>
 *   RAM_TOTAL_KB=<kb>
 *   CPU_PERMILL=<0-1000>
 * ---------------------------------------------------------------------------*/
long get_container_uptime(pid_t pid) {
  if (pid <= 0)
    return -1;

  long clk_tck = sysconf(_SC_CLK_TCK);
  if (clk_tck <= 0)
    clk_tck = 100;

  char stat_path[PATH_MAX];
  snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", (int)pid);

  unsigned long long start_ticks = 0;
  {
    auto_fclose FILE *f = fopen(stat_path, "r");
    if (!f)
      return -1;
    /* starttime is the 22nd field */
    for (int i = 1; i <= 21; i++) {
      if (fscanf(f, "%*s") == EOF)
        break;
    }
    if (fscanf(f, "%llu", &start_ticks) != 1)
      start_ticks = 0;
  }
  if (start_ticks == 0)
    return -1;

  {
    auto_fclose FILE *f = fopen("/proc/uptime", "r");
    if (!f)
      return -1;
    double host_uptime_sec = 0.0;
    if (fscanf(f, "%lf", &host_uptime_sec) != 1)
      host_uptime_sec = 0.0;
    long uptime_sec = (long)(host_uptime_sec - (double)start_ticks / (double)clk_tck);
    return (uptime_sec < 0) ? 0 : uptime_sec;
  }
}

void format_uptime(long uptime_sec, char *buf, size_t size) {
  if (uptime_sec < 0) {
    safe_strncpy(buf, "unknown", size);
    return;
  }

  int days = uptime_sec / 86400;
  int hours = (uptime_sec % 86400) / 3600;
  int mins = (uptime_sec % 3600) / 60;
  int secs = uptime_sec % 60;

  char tmp[128] = {0};
  int pos = 0;

  if (days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dd ", days);
  if (hours > 0 || days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dh ", hours);
  if (mins > 0 || hours > 0 || days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dm ", mins);
  snprintf(tmp + pos, sizeof(tmp) - pos, "%ds", secs);

  safe_strncpy(buf, tmp, size);
}

int show_container_usage(cfg_t *cfg) {
  pid_t pid = 0;

  if (!is_container_running(cfg, &pid) || pid <= 0) {
    log_error("Container '%s' is not running.", cfg->container_name);
    return -1;
  }

  /* -----------------------------------------------------------------------
   * UPTIME
   * -----------------------------------------------------------------------*/
  long uptime_sec = get_container_uptime(pid);
  char uptime_str[128];
  format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));

  /* -----------------------------------------------------------------------
   * PID namespace of container init
   * -----------------------------------------------------------------------*/
  char ns_init_path[PATH_MAX];
  snprintf(ns_init_path, sizeof(ns_init_path), "/proc/%d/ns/pid", (int)pid);
  char container_ns[256] = {0};
  ssize_t ns_len =
      readlink(ns_init_path, container_ns, sizeof(container_ns) - 1);
  if (ns_len <= 0) {
    log_error("Failed to read PID namespace of container init: %s",
              strerror(errno));
    return -1;
  }
  container_ns[ns_len] = '\0';

  /* -----------------------------------------------------------------------
   * WALK 1: collect RAM + CPU sample 1 in a single /proc pass
   * -----------------------------------------------------------------------*/
  long ram_used_kb = 0;
  long long cpu_t1 = 0;
  long long cpu_host_t1 = 0;

  auto_closedir DIR *proc_dir = opendir("/proc");
  if (!proc_dir) {
    log_error("Failed to open /proc: %s", strerror(errno));
    return -1;
  }
  struct dirent *de;
  while ((de = readdir(proc_dir)) != nullptr) {
    if (de->d_name[0] < '1' || de->d_name[0] > '9')
      continue;

    /* check PID namespace */
    char ns_path[PATH_MAX];
    snprintf(ns_path, sizeof(ns_path), "/proc/%s/ns/pid", de->d_name);
    char ns_buf[256] = {0};
    ssize_t r = readlink(ns_path, ns_buf, sizeof(ns_buf) - 1);
    if (r <= 0)
      continue;
    ns_buf[r] = '\0';
    if (strcmp(ns_buf, container_ns) != 0)
      continue;

    /* RAM: VmRSS from /proc/<pid>/status */
    char status_path[PATH_MAX];
    snprintf(status_path, sizeof(status_path), "/proc/%s/status", de->d_name);
    auto_fclose FILE *sf = fopen(status_path, "r");
    if (sf) {
      char line[128];
      while (fgets(line, sizeof(line), sf)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
          long rss = 0;
          if (sscanf(line + 6, "%ld", &rss) == 1)
            ram_used_kb += rss;
          break;
        }
      }
    }

    /* CPU sample 1: utime+stime from /proc/<pid>/stat fields 14+15 */
    char pstat_path[PATH_MAX];
    snprintf(pstat_path, sizeof(pstat_path), "/proc/%s/stat", de->d_name);
    auto_fclose FILE *pf = fopen(pstat_path, "r");
    if (pf) {
      long long utime = 0, stime = 0;
      for (int i = 1; i <= 13; i++)
        if (fscanf(pf, "%*s") == EOF)
          break;
      if (fscanf(pf, "%lld %lld", &utime, &stime) == 2)
        cpu_t1 += utime + stime;
    }
  }

  /* host CPU total sample 1 */
  {
    auto_fclose FILE *f = fopen("/proc/stat", "r");
    if (f) {
      long long u, n, s, i, iow, irq, sirq;
      if (fscanf(f, "cpu %lld %lld %lld %lld %lld %lld %lld", &u, &n, &s, &i,
                 &iow, &irq, &sirq) == 7)
        cpu_host_t1 = u + n + s + i + iow + irq + sirq;
    }
  }

  /* total device RAM from /proc/meminfo */
  long ram_total_kb = 0;
  {
    auto_fclose FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
      char line[128];
      while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
          sscanf(line + 9, "%ld", &ram_total_kb);
          break;
        }
      }
    }
  }

  /* 250ms measurement window - short enough for a responsive UI,
   * long enough for a meaningful CPU delta (1 jiffie = 10ms at HZ=100,
   * so 250ms gives 25-jiffie resolution = ~0.4% minimum granularity). */
  struct timespec ts = {0, 250000000L};
  nanosleep(&ts, nullptr);

  /* -----------------------------------------------------------------------
   * WALK 2: CPU sample 2 only
   * -----------------------------------------------------------------------*/
  long long cpu_t2 = 0;
  long long cpu_host_t2 = 0;

  {
    auto_closedir DIR *proc_dir2 = opendir("/proc");
    if (proc_dir2) {
      while ((de = readdir(proc_dir2)) != nullptr) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
          continue;
        char ns_path[PATH_MAX];
        snprintf(ns_path, sizeof(ns_path), "/proc/%s/ns/pid", de->d_name);
        char ns_buf[256] = {0};
        ssize_t r = readlink(ns_path, ns_buf, sizeof(ns_buf) - 1);
        if (r <= 0)
          continue;
        ns_buf[r] = '\0';
        if (strcmp(ns_buf, container_ns) != 0)
          continue;

        char pstat_path[PATH_MAX];
        snprintf(pstat_path, sizeof(pstat_path), "/proc/%s/stat", de->d_name);
        auto_fclose FILE *pf2 = fopen(pstat_path, "r");
        if (pf2) {
          long long utime = 0, stime = 0;
          for (int i = 1; i <= 13; i++)
            if (fscanf(pf2, "%*s") == EOF)
              break;
          if (fscanf(pf2, "%lld %lld", &utime, &stime) == 2)
            cpu_t2 += utime + stime;
        }
      }
    }
  }

  {
    auto_fclose FILE *f = fopen("/proc/stat", "r");
    if (f) {
      long long u, n, s, i, iow, irq, sirq;
      if (fscanf(f, "cpu %lld %lld %lld %lld %lld %lld %lld", &u, &n, &s, &i,
                 &iow, &irq, &sirq) == 7)
        cpu_host_t2 = u + n + s + i + iow + irq + sirq;
    }
  }

  long long delta_container = cpu_t2 - cpu_t1;
  long long delta_host = cpu_host_t2 - cpu_host_t1;
  if (delta_container < 0)
    delta_container = 0;
  long cpu_permill =
      (delta_host > 0) ? (long)(delta_container * 1000 / delta_host) : 0;
  if (cpu_permill > 1000)
    cpu_permill = 1000;

  /* -----------------------------------------------------------------------
   * Output - machine-parseable key=value, one per line
   * -----------------------------------------------------------------------*/
  printf("UPTIME_SEC=%ld\n", uptime_sec);
  printf("UPTIME=%s\n", uptime_str);
  printf("RAM_USED_KB=%ld\n", ram_used_kb);
  printf("RAM_TOTAL_KB=%ld\n", ram_total_kb);
  printf("CPU_PERMILL=%ld\n", cpu_permill);

  return 0;
}

/* ---------------------------------------------------------------------------
 * Bind Mount Sorting
 * ---------------------------------------------------------------------------*/

static int compare_bind_mounts(const void *a, const void *b) {
  const struct bind_mount *ma = (const struct bind_mount *)a;
  const struct bind_mount *mb = (const struct bind_mount *)b;
  return strcmp(ma->dest, mb->dest);
}

void sort_bind_mounts(cfg_t *cfg) {
  if (!cfg || cfg->bind_count <= 1 || !cfg->binds)
    return;

  qsort(cfg->binds, cfg->bind_count, sizeof(struct bind_mount),
        compare_bind_mounts);
}

int validate_container_name(const char *name) {
  if (!name || !name[0])
    return 0;

  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  size_t len = strlen(name);
  if (len >= 256)
    return 0;

  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)name[i];
    if (!(isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' '))
      return 0;
  }

  return 1;
}

int reject_container_name(const char *name) {
  if (!validate_container_name(name)) {
    log_error("Invalid container name '%s'. Use only letters, numbers, "
              "'.', '_', '-' and spaces.",
              name);
    return -1;
  }
  return 0;
}

int validate_bind_destination(const char *dest) {
  if (!dest || dest[0] != '/' || dest[1] == '\0')
    return 0;

  if (strlen(dest) >= PATH_MAX)
    return 0;

  const char *p = dest;
  while (*p) {
    while (*p == '/')
      p++;
    const char *start = p;
    while (*p && *p != '/')
      p++;
    size_t len = (size_t)(p - start);
    if (len == 0)
      continue;
    if ((len == 1 && start[0] == '.') ||
        (len == 2 && start[0] == '.' && start[1] == '.'))
      return 0;
    for (size_t i = 0; i < len; i++) {
      if (iscntrl((unsigned char)start[i]))
        return 0;
    }
  }

  return 1;
}

/*
 * count_folders : function to count the number of folders in the passed path
 * and return the number of folder it can be used the get the total number of
 * containers from the get_runtime_dir directory
 */
int count_folders(const char *path) {
  auto_closedir DIR *dir = opendir(path);
  struct dirent *entry;
  struct stat st;
  char fullpath[PATH_MAX];
  int count = 0;

  if (!dir)
    return 0;

  size_t base_len = strlen(path);

  while ((entry = readdir(dir)) != nullptr) {

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    /* Skip entries whose full path would exceed PATH_MAX */
    if (base_len + 1 + strlen(entry->d_name) >= sizeof(fullpath))
      continue;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

    if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode))
      count++;
  }

  return count;
}

/* Validate each comma-separated name in optarg; store raw value in out_buf. */
int parse_and_validate_names(const char *arg, char *out_buf,
                             size_t out_size) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", arg);
  char *sp, *tok = strtok_r(tmp, ",", &sp);
  while (tok) {
    if (reject_container_name(tok) < 0)
      return -1;
    tok = strtok_r(nullptr, ",", &sp);
  }
  snprintf(out_buf, out_size, "%s", arg);
  return 0;
}

/* Init an iter_cfg suitable for per-container dispatch. */
static void init_iter_cfg(cfg_t *c, const char *prog_name) {
  memset(c, 0, sizeof(*c));
  if (prog_name)
    safe_strncpy(c->prog_name, prog_name, sizeof(c->prog_name));
}

int multi_stop(const char *raw_names) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", raw_names);
  int ret = 0;
  char *sp, *tok = strtok_r(tmp, ",", &sp);
  while (tok) {
    cfg_t c;
    init_iter_cfg(&c, nullptr);
    safe_strncpy(c.container_name, tok, sizeof(c.container_name));
    if (stop_rootfs(&c, 0) != 0)
      ret = 1;
    tok = strtok_r(nullptr, ",", &sp);
  }
  return ret;
}

/* Set oom_score_adj to -1000 (unkillable).  Best-effort, no error return. */
void oom_protect(void) {
  auto_fclose FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f)
    fprintf(f, "-1000\n");
}
