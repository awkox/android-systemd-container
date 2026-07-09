#include "asc.h"

int ensure_runtime(void) {
  create_directories_with_permission(runtime_dir);

  return 0;
}
