#include "asc.h"

const fs::path get_lock_dir() {
  return runtime_dir / "lock";
}

const fs::path get_logs_dir() {
  return runtime_dir / "logs";
}

int ensure_runtime(void) {
  create_directories_with_permission(runtime_dir);
  create_directories_with_permission(get_lock_dir());
  create_directories_with_permission(get_logs_dir());

  return 0;
}
