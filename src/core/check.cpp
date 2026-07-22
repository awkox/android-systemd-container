#include <array>
#include <cerrno>
#include <filesystem>
#include <sched.h>
#include <stdlib.h>
#include <string_view>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core.h"
#include "utils/log.h"

namespace asc::core {

namespace {

bool check_ns(const int flag, std::string_view name) {
  /* 1. 通过 /proc 快速检查内核支持 */
  if (!std::filesystem::exists(std::filesystem::path("/proc/self/ns") / name))
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

bool check_pivot_root() {
  /*
   * 探测 pivot_root 系统调用是否存在，而不实际执行携带危险参数的调用。
   * 我们通过传递无效指针 (nullptr) 检查该系统调用是否已实现；
   * 如果返回 ENOSYS，说明内核未提供。如果返回 EFAULT 或 EINVAL，说明其存在。
   */
  if (syscall(SYS_pivot_root, nullptr, nullptr) < 0 && errno == ENOSYS)
    return false;
  return true;
}

bool check_pidfd_supported() {
  // 传一个不存在的负数 PID 给 pidfd_open，如果是 ENOSYS 说明内核不支持
  // 如果是 EINVAL 或 ESRCH，说明系统调用存在（支持）。
  if (syscall(SYS_pidfd_open, -1, 0) < 0 && errno == ENOSYS)
    return false;
  return true;
}

struct NsCheck {
  int flag;
  std::string_view name;
  std::string_view label;
};

constexpr auto ns_checks = std::to_array<NsCheck>({
    {CLONE_NEWNS, "mnt", "MNT 命名空间"},
    {CLONE_NEWPID, "pid", "PID 命名空间"},
    {CLONE_NEWUTS, "uts", "UTS 命名空间"},
    {CLONE_NEWIPC, "ipc", "IPC 命名空间"},
    {CLONE_NEWCGROUP, "cgroup", "CGROUP 命名空间"},
});

} // namespace

int check_requirements_hw() {
  int missing = 0;

  for (const auto &[flag, name, label] : ns_checks) {
    if (!check_ns(flag, name)) {
      log_error("当前内核不支持 {}", label);
      missing++;
    }
  }

  if (!check_pivot_root()) {
    log_error("当前内核不支持 pivot_root 系统调用");
    missing++;
  }

  if (!check_pidfd_supported()) {
    log_error("当前内核不支持 pidfd 系统调用");
    missing++;
  }

  if (missing > 0) {
    log_error("缺少 {} 项【必须】功能 - 无法继续启动过程", missing);
    return -1;
  }
  return 0;
}

} // namespace asc::core