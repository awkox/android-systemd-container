#include "asc.h"

void rotate_log(const char *path, size_t max_size) {
  struct stat st;
  if (stat(path, &st) == 0 && (size_t)st.st_size >= max_size) {
    char old_path[PATH_MAX + 8];
    snprintf(old_path, sizeof(old_path), "%s.old", path);
    rename(path, old_path);
  }
}

static void write_to_log_file(const char *name, const char *component,
                              const char *raw_msg, int pre_opened_fd) {
  if (!name || !name[0])
    return;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm;
  localtime_r(&ts.tv_sec, &tm);

  /* Pre-opened FD path: survives pivot_root / mount namespace changes.
   * dprintf() writes directly to the fd - no dup/fdopen/fclose overhead.
   * O_APPEND (set at open time) makes each write atomic for small messages. */
  if (pre_opened_fd >= 0) {
    /* In-place rotation: truncate when over 2MB.
     * rename() is not possible since the FD follows the inode, not the path. */
    struct stat st;
    if (fstat(pre_opened_fd, &st) == 0 &&
        (size_t)st.st_size >= 2 * 1024 * 1024) {
      if (ftruncate(pre_opened_fd, 0) < 0) {
        /* best-effort, ignore */
      }
      if (lseek(pre_opened_fd, 0, SEEK_SET) == (off_t)-1) {
        /* best-effort, ignore */
      }
    }
    dprintf(pre_opened_fd, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
            tm.tm_sec, ts.tv_nsec / 1000000, component, raw_msg);
    return;
  }

  /* Fallback: open by path (pre-pivot, monitor process, etc.) */
  char log_dir[PATH_MAX];
  char safe_log_name[256];
  sanitize_container_name(name, safe_log_name, sizeof(safe_log_name));
  snprintf(log_dir, sizeof(log_dir), "%.2048s/" RUNTIME_LOGS_SUBDIR "/%.256s",
           get_runtime_dir(), safe_log_name);
  mkdir_p(log_dir, 0755);

  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%.4090s/log", log_dir);

  rotate_log(log_path, 2 * 1024 * 1024);

  auto_fclose FILE *f = fopen(log_path, "ae"); /* append + close-on-exec */
  if (!f)
    return;

  fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s\n",
          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
          tm.tm_sec, ts.tv_nsec / 1000000, component, raw_msg);
}

[[gnu::format(printf, 4, 5)]]
void log_internal(const char *prefix, const char *color,
                  bool is_err, const char *fmt, ...) {
  char raw_msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
  va_end(ap);

  /* Always log to file if container name is known */
  if (log_container_name[0]) {
    write_to_log_file(log_container_name, "main", raw_msg, log_container_fd);
  }

  /* Decide if we should print to terminal */
  if (log_silent && !is_err)
    return;

  if (!is_err) {
    if (strncmp(raw_msg, "[CGROUP]", 8) == 0 ||
        strncmp(raw_msg, "[VIRT]", 6) == 0 ||
        strncmp(raw_msg, "[NET]", 5) == 0 ||
        strncmp(raw_msg, "[SEC]", 5) == 0 ||
        strncmp(raw_msg, "[GPU]", 5) == 0 ||
        strncmp(raw_msg, "[FW]", 4) == 0
    ) {
      return;
    }
  }

  FILE *out = is_err ? stderr : stdout;
  fprintf(out,
          "["
          "%s"
          "%s" C_RESET "] %s\r\n",
          color, prefix, raw_msg);
  fflush(out);
}

[[gnu::format(printf, 1, 2)]]
void die_internal(const char *fmt, ...) {
  char raw_msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
  va_end(ap);

  if (log_container_name[0]) {
    write_to_log_file(log_container_name, "fatal", raw_msg, log_container_fd);
  }

  fprintf(stderr, "[" C_RED "-" C_RESET "] %s\r\n", raw_msg);
  fflush(stderr);
  exit(EXIT_FAILURE);
}

void write_monitor_debug_log(const char *name, const char *fmt, ...) {
  if (!name || !name[0] || !fmt)
    return;

  char raw_msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
  va_end(ap);

  write_to_log_file(name, "monitor", raw_msg, -1);
}

void print_privileged_warning(int privileged_mask) {
  if (privileged_mask <= 0)
    return;

  printf(C_BOLD C_RED "WARNING: PRIVILEGED MODE ACTIVE - DEVICE SECURITY "
                      "COMPROMISED" C_RESET "\r\n\r\n");
  fflush(stdout);
}

void open_container_log(cfg_t *cfg) {
  if (!cfg || !cfg->container_name[0])
    return;

  char log_dir[PATH_MAX];
  char safe_log_name[256];
  sanitize_container_name(cfg->container_name, safe_log_name,
                          sizeof(safe_log_name));
  snprintf(log_dir, sizeof(log_dir), "%.2048s/" RUNTIME_LOGS_SUBDIR "/%.256s",
           get_runtime_dir(), safe_log_name);
  mkdir_p(log_dir, 0755);

  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%.4090s/log", log_dir);

  rotate_log(log_path, 2 * 1024 * 1024);

  int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd >= 0)
    log_container_fd = fd;
}

void close_container_log(void) {
  if (log_container_fd >= 0) {
    close(log_container_fd);
    log_container_fd = -1;
  }
}
