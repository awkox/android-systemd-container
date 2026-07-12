#include "asc.h"

/* 使用 std::array 替代 C 风格数组，移除 -1 哨兵值 */
static constexpr auto universal_drops = std::to_array<int>({
  CAP_SYS_MODULE
});

static constexpr auto caps_to_drop = std::to_array<int>({
  CAP_SYS_RAWIO,       /* 原始的硬件 I/O 访问 (端口, 内存) */
  CAP_SYS_PTRACE,      /* 允许跨命名空间跟踪或注入进程 */
  CAP_SYS_PACCT,       /* 进程审计记录 */
  CAP_SYSLOG,          /* 内核日志(dmesg)读取与控制 */
  CAP_MAC_ADMIN,       /* 强制访问控制 (MAC) 策略修改 */
  CAP_MAC_OVERRIDE,    /* 绕过 MAC 策略 */
  CAP_WAKE_ALARM,      /* 影响宿主机电源管理/唤醒 */
  CAP_BLOCK_SUSPEND,   /* 阻止宿主机休眠 */
  CAP_AUDIT_READ,      /* 读取内核审计日志 */
  CAP_DAC_READ_SEARCH  /* 绕过文件读取和目录搜索的权限检查 */
});

/*
 * apply_capability_hardening()
 * 从环境边界集中移除危险的 capabilities 以缩减容器的攻击面。
 */
void apply_capability_hardening(const int privileged_mask) {
  if (privileged_mask & PRIV_NOCAPS) {
    log_info("[SEC] 已激活 privileged=nocaps: 跳过 Capabilities 裁剪。");
    return;
  }

  // 定义泛型 Lambda 来处理任意容器的 Capability 丢弃逻辑
  auto drop_caps = [](const auto& caps) -> int {
    int dropped_count = 0;
    // 1. 基于范围的 for 循环，无需判断 -1
    for (const int cap : caps) {
      if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
        if (errno != EINVAL) {
          // 2. 使用 C++11 的 system_category 替代非线程安全的 strerror
          // 注意：.c_str() 是为了兼容你现有的 C 风格 log_warn 函数
          log_warn("[SEC] 无法移除 Cap %d: %s", cap, 
                   std::system_category().message(errno).c_str());
        }
      } else {
        dropped_count++;
      }
    }
    return dropped_count;
  };

  // 3. 复用逻辑，直接累加结果
  int total_dropped = drop_caps(universal_drops) + drop_caps(caps_to_drop);

  log_info("[SEC] 已完成内核权限边界裁剪 (共移除了 %d 个 Cap)。", total_dropped);
}
