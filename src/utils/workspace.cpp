#include "asc.h"

int ensure_runtime(void) {
  if (cgroup_host_bootstrap() < 0) {
    return -1;
  }

  create_directories_with_permission(runtime_dir);
  create_directories_with_permission(lock_dir);      // 修复获取锁直接失败的致命错误
  create_directories_with_permission(config_dir);    // 规范化预创建
  return 0;
}