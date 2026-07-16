#include <csignal>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <poll.h>
#include <sys/syscall.h>
#include "core/container.h"
#include "core/state.h"
#include "utils/log.h"

constexpr int STOP_TIMEOUT = 15;

static int stop_rootfs_with_timeout(std::string_view container_name, int timeout_seconds) {
  if (acquire_external_lock(container_name) != 0) {
    log_error("无法停止 '%s': 另一个命令正在管理此容器",
              container_name.data());
    return -1;
  }

  pid_t pid = -1;
  if (!is_container_running(container_name, pid)) {
    log_error("容器 '%s' 未运行或状态无效。", container_name.data());
    release_external_lock();
    return -1;
  }

  log_info("正在停止容器 '%s' (PID %d)...", container_name.data(), pid);

  int pfd = syscall(SYS_pidfd_open, pid, 0);
  if (pfd < 0) {
    log_error("pidfd_open失败：%s", strerror(errno));
    release_external_lock();
    return -1;
  }

  bool unkillable = false;
  syscall(SYS_pidfd_send_signal, pfd, SIGRTMIN + 3, nullptr, 0);

  pollfd pfd_poll = {.fd = pfd, .events = POLLIN, .revents = 0};
  int r = poll(&pfd_poll, 1, timeout_seconds * 1000);
  if (!(r > 0 && (pfd_poll.revents & POLLIN))) {
    log_warn("超时，正在发送 SIGKILL 信号...");
    syscall(SYS_pidfd_send_signal, pfd, SIGKILL, nullptr, 0);
    r = poll(&pfd_poll, 1, 5000); // 5 sec max wait for SIGKILL
    if (!(r > 0 && (pfd_poll.revents & POLLIN))) {
      unkillable = true;
      log_error("容器进程 (PID %d) 进入了不可杀死的僵尸状态！", pid);
      log_warn("这通常是因为内核僵尸进程导致。\n将尽最大努力清理宿主机资源 (无数据同步)...");
    }
  }
  close(pfd);

  if (!unkillable) {
    log_info("已成功终止容器 '%s'。资源清理已移交后台 Monitor 完成。", container_name.data());
  }

  release_external_lock();
  return unkillable ? -1 : 0;
}

int stop_rootfs(std::string_view container_name) {
  return stop_rootfs_with_timeout(container_name, STOP_TIMEOUT);
}