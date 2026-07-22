#include "utils/workspace.h"
#include "oci.h"
#include "utils/fileio.h"
#include "utils/path.h"

int ensure_runtime() {
  if (asc::oci::cgroup_host_bootstrap() < 0) {
    return -1;
  }

  create_directories_with_permission(runtime_dir);
  create_directories_with_permission(lock_dir); // 修复获取锁直接失败的致命错误
  return 0;
}
