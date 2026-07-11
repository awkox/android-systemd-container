#include "asc.h"

static int stop_rootfs_with_timeout(const asc_rt_t *rt, int timeout_seconds) {
  if (timeout_seconds < 0)
    timeout_seconds = STOP_TIMEOUT;

  if (acquire_external_lock(rt->container_name) != 0) {
    log_error("无法停止 '%s': 另一个命令正在管理此容器",
              rt->container_name);
    return -1;
  }

  pid_t pid = 0;
  if (!is_container_running(rt->container_name, &pid)) {
    log_error("容器 '%s' 未运行或状态无效。", rt->container_name);
    release_external_lock();
    return -1;
  }

  log_info("正在停止容器 '%s' (PID %d)...", rt->container_name, pid);

  kill(pid, SIGRTMIN + 3);

  log_info("正在等待容器优雅关闭 (最长可能需要 %d 秒)...", timeout_seconds);

  bool stopped = false;
  for (int i = 0; i < timeout_seconds * 5; i++) {
    if (kill(pid, 0) < 0) {
      if (errno == ESRCH) {
        stopped = true;
        break;
      }
    }
    usleep(RETRY_DELAY_US);
  }

  bool unkillable = false;
  if (!stopped) {
    log_warn("优雅关闭超时，正在发送 SIGKILL 信号...");
    kill(pid, SIGKILL);

    bool killed = false;
    for (int j = 0; j < 25; j++) {
      if (kill(pid, 0) < 0 && errno == ESRCH) {
        killed = true;
        break;
      }
      usleep(RETRY_DELAY_US);
    }

    if (!killed) {
      unkillable = true;
      log_error("容器进程 (PID %d) 进入了不可杀死的僵尸状态！", pid);
      log_warn("这通常是因为内核僵尸进程导致。\n将尽最大努力清理宿主机资源 (无数据同步)...");
    }
  }

  cleanup_container_resources(rt, unkillable);

  if (!rt->foreground)
    log_info("容器 '%s' 已停止。", rt->container_name);

  release_external_lock();

  return 0;
}

int stop_rootfs(const asc_rt_t *rt) {
  return stop_rootfs_with_timeout(rt, STOP_TIMEOUT);
}