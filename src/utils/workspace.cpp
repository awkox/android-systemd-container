#include "asc.h"

const fs::path get_runtime_dir() {
  return fs::path("/tmp/asc");
}

const fs::path get_lock_dir() {
  return get_runtime_dir() / "lock";
}

const fs::path get_logs_dir() {
  return get_runtime_dir() / "logs";
}

int ensure_runtime(void) {
  create_directories_with_permission(get_runtime_dir());
  create_directories_with_permission(get_lock_dir());
  create_directories_with_permission(get_logs_dir());

  return 0;
}
