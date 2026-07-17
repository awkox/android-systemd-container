#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <cerrno>
#include <filesystem>
#include <string_view>
#include <cstring>
#include <csignal>
#include <string>

#include "core.h"
#include "utils/log.h"
#include "utils/workspace.h"
#include "platform/pty.h"
#include "platform/console.h"
#include "common.h"

namespace asc::core {

namespace {

constexpr int STOP_TIMEOUT = 15;

}

int stop_rootfs(std::string_view container_name) {
  if (acquire_external_lock(container_name) != 0) {
    log_error("无法停止 '{}': 另一个命令正在管理此容器", container_name);
    return -1;
  }

  pid_t pid = -1;
  if (!is_container_running(container_name, pid)) {
    log_error("容器 '{}' 未运行或状态无效。", container_name);
    release_external_lock();
    return -1;
  }

  log_info("正在停止容器 '{}' (PID {})...", container_name, pid);

  int pfd = syscall(SYS_pidfd_open, pid, 0);
  if (pfd < 0) {
    log_error("pidfd_open失败：{}", strerror(errno));
    release_external_lock();
    return -1;
  }

  bool unkillable = false;
  syscall(SYS_pidfd_send_signal, pfd, SIGRTMIN + 3, nullptr, 0);

  pollfd pfd_poll = {.fd = pfd, .events = POLLIN, .revents = 0};
  int r = poll(&pfd_poll, 1, STOP_TIMEOUT * 1000);
  if (!(r > 0 && (pfd_poll.revents & POLLIN))) {
    log_warn("超时，正在发送 SIGKILL 信号...");
    syscall(SYS_pidfd_send_signal, pfd, SIGKILL, nullptr, 0);
    r = poll(&pfd_poll, 1, 5000); 
    if (!(r > 0 && (pfd_poll.revents & POLLIN))) {
      unkillable = true;
      log_error("容器进程 (PID {}) 进入了不可杀死的僵尸状态！", pid);
    }
  }
  close(pfd);

  if (!unkillable) {
    log_info("已成功终止容器 '{}'。资源清理已移交后台 Monitor 完成。", container_name);
  }

  release_external_lock();
  return unkillable ? -1 : 0;
}

int start_rootfs(const char *container_name, const char *config_path) {
  bool lock_acquired = false;
  int sync_pipe[2] = {-1, -1};
  pid_t monitor_pid = -1;
  pid_t existing_pid = -1;
  asc::rt rt = {};

  ensure_runtime();

  log_info("正在获取容器独占锁与资源...");
  if (acquire_external_lock(container_name) != 0) {
    if (is_container_running(container_name, existing_pid)) {
      log_error("容器名称 '{}' 已被 PID {} 占用。", container_name, existing_pid);
    } else {
      log_error("无法操作容器 '{}': 另一个管理命令正在执行。", container_name);
    }
    goto cleanup;
  }
  lock_acquired = true;

  if (is_container_running(container_name, existing_pid)) {
    log_error("容器名称 '{}' 已被 PID {} 占用。", container_name, existing_pid);
    goto cleanup;
  }

  if (check_requirements_hw() < 0) return 1;

  if (config_path[0]) {
    if (config_load(config_path, rt.conf) < 0) {
      log_error("无法从 '{}' 加载配置: {}", config_path, strerror(errno));
      goto cleanup;
    }
  }

  rt.foreground = true;
  if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
    rt.foreground = false;
    log_warn("无交互式终端 - 自动转入后台运行。");
  }

  log_info("正在分配并设置容器虚拟控制台 (PTY Console)...");
  if (terminal_create(rt.console) < 0) {
    log_error("无法分配容器控制台 (Console) PTY");
    goto cleanup;
  }

  if (isatty(STDIN_FILENO)) {
    winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(rt.console.master, TIOCSWINSZ, &ws);
  }

  if (pipe(sync_pipe) < 0) {
    log_error("创建管道失败: {}", strerror(errno));
    goto cleanup;
  }
  fcntl(sync_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl(sync_pipe[1], F_SETFD, FD_CLOEXEC);

  rt.container_name = container_name;

  log_info("正在孵化 Monitor 监控守护进程...");
  monitor_pid = fork();
  if (monitor_pid < 0) {
    close(sync_pipe[0]);
    close(sync_pipe[1]);
    sync_pipe[0] = -1;
    sync_pipe[1] = -1;
    log_error("fork(Monitor) 失败: {}", strerror(errno));
    goto cleanup;
  }

  if (monitor_pid == 0) {
    close(sync_pipe[0]);
    sync_pipe[0] = -1;
    if (rt.console.master >= 0) {
      close(rt.console.master);
      rt.console.master = -1;
    }

    // 子进程仅需关闭锁文件的 fd 而不应释放锁文件本身
    close_external_lock_fd();

    monitor_run(rt, sync_pipe[1]);
    _exit(EXIT_FAILURE);
  }

  close(sync_pipe[1]);
  sync_pipe[1] = -1;

  if (rt.console.slave >= 0) {
    close(rt.console.slave);
    rt.console.slave = -1;
  }

  if (read(sync_pipe[0], &rt.container_pid, sizeof(pid_t)) != sizeof(pid_t)) {
    log_error("Monitor 监控进程未能发送容器 PID。");
    goto cleanup;
  }
  close(sync_pipe[0]);
  sync_pipe[0] = -1;

  if (lock_acquired) release_external_lock();

  if (rt.foreground) {
    return console_monitor_loop(rt.console.master, monitor_pid, rt.container_name);
  }

  if (rt.console.master >= 0) {
    close(rt.console.master);
    rt.console.master = -1;
  }

  return 0;

cleanup:
  if (lock_acquired) release_external_lock();

  if (rt.console.master >= 0) {
    close(rt.console.master);
    rt.console.master = -1;
  }
  if (rt.console.slave >= 0) {
    close(rt.console.slave);
    rt.console.slave = -1;
  }
  if (sync_pipe[0] >= 0) close(sync_pipe[0]);
  if (sync_pipe[1] >= 0) close(sync_pipe[1]);

  return -1;
}

}