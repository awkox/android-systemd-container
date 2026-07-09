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
  fs::create_directories(get_runtime_dir());
  fs::create_directories(get_lock_dir());
  fs::create_directories(get_logs_dir());

  return 0;
}
