#include "asc.h"

static int stop_rootfs_with_timeout(cfg_t *cfg, int timeout_seconds) {
  if (timeout_seconds < 0)
    timeout_seconds = STOP_TIMEOUT;

  if (acquire_external_lock(cfg->conf.container_name) != 0) {
    log_error("无法停止 '%s': 另一个命令正在管理此容器",
              cfg->conf.container_name);
    return -1;
  }

  pid_t pid = 0;
  if (!is_container_running(cfg->conf.uuid, &pid) || pid <= 0) {
    log_error("容器 '%s' 未运行或状态无效。", cfg->conf.container_name);
    release_external_lock();
    return -1;
  }

  log_info("正在停止容器 '%s' (PID %d)...", cfg->conf.container_name, pid);

  if (cfg->conf.img_mount_point[0] == '\0') {
    read_proc_environ(pid, "RUNTIME_MOUNT_PATH", cfg->conf.img_mount_point,
                      sizeof(cfg->conf.img_mount_point));
  }

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

  if (cfg->conf.img_mount_point[0] && !unkillable && cfg->conf.hw_access) {
    char fw_path[PATH_MAX + 16];
    build_firmware_path(cfg->conf.img_mount_point, fw_path, sizeof(fw_path));
    firmware_path_remove(fw_path);
  }

  cleanup_container_resources(cfg, unkillable);

  if (!cfg->rt.foreground)
    log_info("容器 '%s' 已停止。", cfg->conf.container_name);

  release_external_lock();

  return 0;
}

int stop_rootfs(cfg_t *cfg) {
  return stop_rootfs_with_timeout(cfg, STOP_TIMEOUT);
}
