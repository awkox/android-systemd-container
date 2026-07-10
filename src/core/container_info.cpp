#include "asc.h"

static const char *get_architecture(void) {
  static struct utsname uts;
  if (uname(&uts) != 0)
    return "unknown";
  return uts.machine;
}

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
    log_error("容器 '%s' 未运行或状态无效。", cfg->rt.container_name);
    return -1;
  }

  const char *arch = get_architecture();
  printf("宿主机架构: %s\n", arch);

  printf("\n容器: %s (运行中)\n",
         cfg->rt.container_name);
  printf("  PID: %d\n", pid);

  if (!trust_cfg_pid) {
    const long uptime_sec = get_container_uptime(pid);
    if (uptime_sec >= 0) {
      char uptime_str[128];
      format_uptime(uptime_sec, uptime_str, sizeof(uptime_str));
      printf("  运行时长: %s\n", uptime_str);
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
    char mask_str[256];
    format_privileged_mask(cfg->conf.privileged_mask, mask_str, sizeof(mask_str));
    printf("  特权模式掩码: %s\n", mask_str);
    feat_count++;
  }

  if (feat_count == 0) {
    printf("  (无)\n");
  }

  if (!trust_cfg_pid &&
      (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit)) {
    long long mu = -1, cu = -1, pu = -1;
    cgroup_get_usage(cfg->rt.container_name, &mu, &cu, &pu);
    printf("\n资源限制与使用状态:\n");

    if (cfg->conf.memory_limit) {
      char used[32] = "?", lim[32];
      if (mu >= 0)
        format_size(mu, used, sizeof(used));
      format_size(cfg->conf.memory_limit, lim, sizeof(lim));
      printf("  内存   : %s / %s\n", used, lim);
    }
    if (cfg->conf.cpu_quota) {
      const long long period = cfg->conf.cpu_period > 0 ? cfg->conf.cpu_period : 100000;
      const double cores = (double)cfg->conf.cpu_quota / period;
      printf("  CPU    : %.2f 核心", cores);
      if (cu >= 0) {
        const long uptime = get_container_uptime(pid);
        if (uptime > 0) {
          const double usage_sec = (double)cu / 1e6;
          const double avg_util = usage_sec / (double)uptime / cores * 100.0;
          printf(" (平均负载: %.1f%%)", avg_util);
        } else {
          printf(" (已用: %.3fs)", (double)cu / 1e6);
        }
      }
      printf("\n");
    }
    if (cfg->conf.pids_limit) {
      printf("  PIDs   : 限制上限 %lld", cfg->conf.pids_limit);
      if (pu >= 0)
        printf(" (当前数量: %lld)", pu);
      printf("\n");
    }
  }

  printf("\n");
  return 0;
}