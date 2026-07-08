#include "asc.h"

/* 必须丢弃的全局能力 (Universal drops) - 即便在硬件直通模式下，
 * 容器内部也没有加载内核模块 (CAP_SYS_MODULE) 的合法用途。
 * 注意：我们刻意保留了 CAP_SYS_BOOT，以便容器内可以执行 reboot(2) 系统调用；
 * 我们刻意保留了 CAP_MKNOD，因为嵌套容器运行时（如 Docker-in-Docker）需要它。*/
static constexpr int universal_drops[] = {
  CAP_SYS_MODULE,
  -1,
};

/* 标准隔离层级：丢弃那些可能影响宿主机稳定性或允许逃逸出容器隔离的能力。 */
static constexpr int caps_to_drop[] = {
  CAP_SYS_RAWIO,       /* 原始的硬件 I/O 访问 (端口, 内存) */
  CAP_SYS_PTRACE,      /* 允许跨命名空间跟踪或注入进程 */
  CAP_SYS_PACCT,       /* 进程审计记录 */
  CAP_SYSLOG,          /* 内核日志(dmesg)读取与控制 */
  CAP_MAC_ADMIN,       /* 强制访问控制 (MAC) 策略修改 */
  CAP_MAC_OVERRIDE,    /* 绕过 MAC 策略 */
  CAP_WAKE_ALARM,      /* 影响宿主机电源管理/唤醒 */
  CAP_BLOCK_SUSPEND,   /* 阻止宿主机休眠 */
  CAP_AUDIT_READ,      /* 读取内核审计日志 */
  CAP_DAC_READ_SEARCH, /* 绕过文件读取和目录搜索的权限检查 - Shocker 逃逸漏洞的核心 */
  -1,
};

/*
 * apply_capability_hardening()
 *
 * 从环境边界集(bounding set)中移除危险的 capabilities 以缩减容器的攻击面。
 */
void apply_capability_hardening(const int privileged_mask) {
  int total_dropped = 0;

  if (privileged_mask & PRIV_NOCAPS) {
    log_info("[SEC] 已激活 privileged=nocaps: 跳过 Capabilities 裁剪。");
    return;
  }

  for (int i = 0; universal_drops[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, universal_drops[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] 无法移除必须禁用的 Cap %d: %s",
                 universal_drops[i], strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  for (int i = 0; caps_to_drop[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, caps_to_drop[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] 无法移除 Cap %d: %s", caps_to_drop[i],
                 strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  log_info("[SEC] 已完成内核权限边界裁剪 (共移除了 %d 个 Cap)。", total_dropped);
}