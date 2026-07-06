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

int generate_uuid(char *buf, const size_t size) {
  if (!buf || size < UUID_LEN + 1)
    return -1;

  unsigned char raw[UUID_LEN / 2];

  /* Primary path: /dev/urandom */
  auto_close const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    const ssize_t r = read(fd, raw, sizeof(raw));

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

    const unsigned int seed =
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
                     const size_t out_size) {
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

int read_proc_environ(const pid_t pid, const char *key, char *value, const size_t size) {
  if (!key || !value || size == 0 || pid <= 0)
    return -1;

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/environ", pid);

  auto_fclose FILE *f = fopen(path, "re");
  if (!f)
    return -1;

  const int keylen = strlen(key);
  int found = -1;

  while (1) {
    int c = fgetc(f);
    if (c == EOF)
      break;

    if (c == key[0]) {
      const long pos = ftell(f);
      if (pos < 0)
        break;
      fseek(f, pos - 1, SEEK_SET);

      bool matched = true;
      for (int i = 0; i < keylen; i++) {
        const int kc = fgetc(f);
        if (kc != (unsigned char)key[i]) {
          matched = false;
          break;
        }
      }
      if (matched && fgetc(f) == '=') {
        int vi = 0;
        while (vi < (int)size - 1) {
          const int vc = fgetc(f);
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

int safe_openat_proc(const pid_t pid, const char *subpath, const int flags, const mode_t mode) {
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
  const char *comp = strtok_r(tmp, "/", &save);
  const char *next = strtok_r(nullptr, "/", &save);

  while (comp && next) {
    const int nextfd =
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
                           const size_t out_size) {
  const size_t token_len = strlen(token);
  const char *p = buf;
  bool first = true;
  out[0] = '\0';

  while (*p) {
    const char *comma = strchr(p, ',');
    const size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);

    if (!(seg_len == token_len && memcmp(p, token, token_len) == 0)) {
      /* Not our token - keep it */
      if (!first)
        strncat(out, ",", out_size - strlen(out) - 1);
      strncat(out, p,
              seg_len < out_size - strlen(out) - 1
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
  const size_t fw_len = strlen(fw_path);
  const char *p = current;
  while (*p) {
    const char *comma = strchr(p, ',');
    const size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);
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
    const size_t needed =
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
  const int new_len = fw_remove_token(current, fw_path, new_path, sizeof(new_path));

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

static int internal_run(char *const argv[], const bool quiet) {
  const pid_t pid = fork();
  if (pid < 0)
    return -1;

  if (pid == 0) {
    if (quiet) {
      auto_close const int devnull = open("/dev/null", O_RDWR);
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

int run_command_quiet(char *const argv[]) {
  return internal_run(argv, true);
}

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
long get_container_uptime(const pid_t pid) {
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
    const long uptime_sec = (long)(host_uptime_sec - (double)start_ticks / (double)clk_tck);
    return uptime_sec < 0 ? 0 : uptime_sec;
  }
}

void format_uptime(const long uptime_sec, char *buf, const size_t size) {
  if (uptime_sec < 0) {
    safe_strncpy(buf, "unknown", size);
    return;
  }

  const int days = uptime_sec / 86400;
  const int hours = uptime_sec % 86400 / 3600;
  const int mins = uptime_sec % 3600 / 60;
  const int secs = uptime_sec % 60;

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

/* ---------------------------------------------------------------------------
 * Bind Mount Sorting
 * ---------------------------------------------------------------------------*/
int validate_container_name(const char *name) {
  if (!name || !name[0])
    return 0;

  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  const size_t len = strlen(name);
  if (len >= 256)
    return 0;

  for (size_t i = 0; i < len; i++) {
    const unsigned char c = (unsigned char)name[i];
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

  const size_t base_len = strlen(path);

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
                             const size_t out_size) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", arg);
  char *sp;
  const char *tok = strtok_r(tmp, ",", &sp);
  while (tok) {
    if (reject_container_name(tok) < 0)
      return -1;
    tok = strtok_r(nullptr, ",", &sp);
  }
  snprintf(out_buf, out_size, "%s", arg);
  return 0;
}

/* Set oom_score_adj to -1000 (unkillable).  Best-effort, no error return. */
void oom_protect(void) {
  auto_fclose FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f)
    fprintf(f, "-1000\n");
}
