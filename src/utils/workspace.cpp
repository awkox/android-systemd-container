#include "asc.h"

const char *get_runtime_dir(void) {
  return "/tmp/asc";
}

const char *get_lock_dir(void) {
  static char lock_path[PATH_MAX];
  snprintf(lock_path, sizeof(lock_path), "%s/%s", get_runtime_dir(),
           "lock");
  return lock_path;
}

const char *get_logs_dir(void) {
  static char logs_path[PATH_MAX];
  snprintf(logs_path, sizeof(logs_path), "%s/%s", get_runtime_dir(),
           "logs");
  return logs_path;
}

int ensure_runtime(void) {
  mkdir_p(get_runtime_dir(), 0755);
  mkdir_p(get_lock_dir(), 0755);
  mkdir_p(get_logs_dir(), 0755);

  return 0;
}
