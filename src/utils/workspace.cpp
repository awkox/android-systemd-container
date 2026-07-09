#include "asc.h"

int ensure_runtime(void) {
  create_directories_with_permission(runtime_dir);

  create_directories_with_permission(lock_dir);      // 修复获取锁直接失败的致命错误
  create_directories_with_permission(log_dir);       // 修复 Daemon 无日志输出的错误
  create_directories_with_permission(config_dir);    // 规范化预创建
  create_directories_with_permission(volatile_dir);  // 规范化预创建
  return 0;
}
