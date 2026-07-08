#include "asc.h"

static bool is_root = false;

static bool check_root(void) {
  is_root = getuid() == 0;
  return is_root;
}

static bool check_ns(const int flag, const char *name) {
  /* 1. 通过 /proc 快速检查内核支持 */
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
  if (access(path, F_OK) != 0)
    return false;

  /* 2. 功能性检查：尝试实际执行 unshare。
   * 因为 unshare() 会影响当前进程，所以我们使用 fork() 来隔离。 */
  const pid_t p = fork();
  if (p < 0)
    return false;

  if (p == 0) {
    if (unshare(flag) < 0) {
      _exit(1);
    }
    _exit(0);
  }

  int status;
  waitpid(p, &status, 0);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool check_pivot_root(void) {
  /* 
   * 探测 pivot_root 系统调用是否存在，而不实际执行携带危险参数的调用。
   * 我们通过传递无效指针 (nullptr) 检查该系统调用是否已实现；
   * 如果返回 ENOSYS，说明内核未提供。如果返回 EFAULT 或 EINVAL，说明其存在。 
   */
  if (syscall(__NR_pivot_root, nullptr, nullptr) < 0 && errno == ENOSYS)
    return false;
  return true;
}

static bool check_kernel_version_supported(void) {
  int major = 0, minor = 0;
  if (get_kernel_version(&major, &minor) < 0)
    return false;
  if (major < MIN_KERNEL_MAJOR)
    return false;
  if (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)
    return false;
  return true;
}

int check_requirements_hw() {
  int missing = 0;

  if (!check_root()) {
    log_error("必须以 root 用户身份运行");
    log_info("本工具需要 root 权限来进行命名空间和挂载操作。");
    missing++;
  }

  /* 功能性命名空间检查 */
  if (!check_ns(CLONE_NEWNS, "mnt")) {
    log_error("当前内核不支持 Mount 命名空间 (挂载隔离)");
    log_info("这是实现文件系统隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWPID, "pid")) {
    log_error("当前内核不支持 PID 命名空间 (进程隔离)");
    log_info("这是实现进程环境隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWUTS, "uts")) {
    log_error("当前内核不支持 UTS 命名空间 (主机名隔离)");
    log_info("这是实现主机名隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWIPC, "ipc")) {
    log_error("当前内核不支持 IPC 命名空间 (进程间通信隔离)");
    log_info("这是实现 IPC 隔离的一项【必须】功能。");
    missing++;
  }

  if (!check_pivot_root()) {
    log_error("当前内核不支持 pivot_root 系统调用");
    log_info(PROJECT_NAME " 必须在支持 pivot_root(而非 ramfs) 的根文件系统上运行。");
    missing++;
  }

  if (!check_kernel_version_supported()) {
    log_error("Linux 内核版本太老");
    log_info(PROJECT_NAME " 至少需要 Linux %d.%d.0 版本的内核。", MIN_KERNEL_MAJOR,
             MIN_KERNEL_MINOR);
    missing++;
  }

  if (missing > 0) {
    printf("\n");
    log_error("缺少 %d 项【必须】功能 - 无法继续启动过程", missing);
    log_info("请运行 './" PROJECT_NAME " check' 来查看完整的系统诊断报告。");
    return -1;
  }

  return 0;
}
