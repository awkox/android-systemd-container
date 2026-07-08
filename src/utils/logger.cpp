#include "asc.h"

bool log_silent = false;
char log_container_name[256] = "";
int log_container_fd = -1;

void rotate_log(const char *path, const size_t max_size) {
  struct stat st;
  if (stat(path, &st) == 0 && static_cast<size_t>(st.st_size) >= max_size) {
    char old_path[PATH_MAX + 8];
    snprintf(old_path, sizeof(old_path), "%s.old", path);
    rename(path, old_path);
  }
}

static void make_container_log_dir(const char *name, char *dir, const size_t size) {
  char safe_log_name[256];
  sanitize_container_name(name, safe_log_name, sizeof(safe_log_name));
  snprintf(dir, size, "%.2048s/" RUNTIME_LOGS_SUBDIR "/%.256s",
           get_runtime_dir(), safe_log_name);
}

static void write_to_log_file(const char *name, const char *component,
                              const char *raw_msg, const int pre_opened_fd) {
  if (!name || !name[0])
    return;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm;
  localtime_r(&ts.tv_sec, &tm);

  if (pre_opened_fd >= 0) {
    struct stat st;
    if (fstat(pre_opened_fd, &st) == 0 &&
        static_cast<size_t>(st.st_size) >= 2 * 1024 * 1024) {
      if (ftruncate(pre_opened_fd, 0) < 0) {}
      if (lseek(pre_opened_fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {}
    }
    dprintf(pre_opened_fd, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
            tm.tm_sec, ts.tv_nsec / 1000000, component, raw_msg);
    return;
  }

  char log_dir[PATH_MAX];
  make_container_log_dir(name, log_dir, sizeof(log_dir));
  mkdir_p(log_dir, 0755);

  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%.4090s/log", log_dir);

  rotate_log(log_path, 2 * 1024 * 1024);

  auto_fclose FILE *f = fopen(log_path, "ae");
  if (!f)
    return;

  fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s\n",
          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
          tm.tm_sec, ts.tv_nsec / 1000000, component, raw_msg);
}

[[gnu::format(printf, 3, 4)]]
void log_internal(const char *prefix, const bool is_err, const char *fmt, ...) {
  char raw_msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
  va_end(ap);

  if (log_container_name[0]) {
    write_to_log_file(log_container_name, "main", raw_msg, log_container_fd);
  }

  if (log_silent && !is_err)
    return;

  if (!is_err) {
    std::string_view sv_msg{raw_msg};
    if (sv_msg.starts_with("[CGROUP]") ||
        sv_msg.starts_with("[VIRT]") ||
        sv_msg.starts_with("[NET]") ||
        sv_msg.starts_with("[SEC]") ||
        sv_msg.starts_with("[GPU]") ||
        sv_msg.starts_with("[FW]")
    ) {
      return;
    }
  }

  FILE *out = is_err ? stderr : stdout;
  fprintf(out, "[%s] %s\r\n", prefix, raw_msg);
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

  fprintf(stderr, "[-] %s\r\n", raw_msg);
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

void print_privileged_warning(const int privileged_mask) {
  if (privileged_mask <= 0)
    return;

  printf("警告: 特权模式(PRIVILEGED)已激活 - 设备安全性已被降级\r\n\r\n");
  fflush(stdout);
}

void open_container_log(cfg_t *cfg) {
  if (!cfg || !cfg->conf.container_name[0])
    return;

  char log_dir[PATH_MAX];
  make_container_log_dir(cfg->conf.container_name, log_dir, sizeof(log_dir));
  mkdir_p(log_dir, 0755);

  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%.4090s/log", log_dir);

  rotate_log(log_path, 2 * 1024 * 1024);

  const int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd >= 0)
    log_container_fd = fd;
}

void close_container_log(void) {
  if (log_container_fd >= 0) {
    close(log_container_fd);
    log_container_fd = -1;
  }
}