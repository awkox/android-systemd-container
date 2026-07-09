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
  mkdir_p(get_runtime_dir().c_str(), 0755);
  mkdir_p(get_lock_dir().c_str(), 0755);
  mkdir_p(get_logs_dir().c_str(), 0755);

  return 0;
}
