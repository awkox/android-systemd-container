#include "asc.h"

int show_info(cfg_t *cfg, const bool trust_cfg_pid) {
  if (!trust_cfg_pid) {
    config_load_by_name(cfg->rt.container_name, cfg);
  }

  pid_t pid = 0;
  if (trust_cfg_pid) {
    pid = cfg->rt.container_pid;
  } else {
    is_container_running(cfg->rt.container_name, &pid);
  }

  if (pid <= 0) {
    log_error("容器 '%s' 未运行或状态无效。", cfg->rt.container_name.c_str());
    return -1;
  }

  printf("\n容器: %s (运行中)\n", cfg->rt.container_name.c_str());
  printf("  PID: %d\n", pid);

  if (!trust_cfg_pid) {
    const long uptime_sec = get_container_uptime(pid);
    if (uptime_sec >= 0) {
      printf("  运行时长: %s\n", format_uptime(uptime_sec).c_str());
    }
  }

  printf("\n已启用特性:\n");
  int feat_count = 0;

  if (cfg->conf.isolation_network) {
    printf("  隔离网络: 是\n");
    feat_count++;
  }

  if (cfg->conf.block_nested_ns) {
    printf("  死锁保护护盾: 是\n");
    feat_count++;
  }

  if (cfg->conf.privileged_mask > 0) {
    std::string mask_str = format_privileged_mask(cfg->conf.privileged_mask);
    printf("  特权模式掩码: %s\n", mask_str.c_str());
    feat_count++;
  }

  if (feat_count == 0) {
    printf("  (无)\n");
  }

  printf("\n");
  return 0;
}