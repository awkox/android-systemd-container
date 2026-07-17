#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <cerrno>
#include <cstring>
#include <array>
#include <system_error>
#include <string>
#include <linux/capability.h>
#include "common.h"
#include "oci.h"
#include "utils/log.h"

namespace asc::oci {

namespace {

/* 使用 std::array 替代 C 风格数组，移除 -1 哨兵值 */
constexpr auto universal_drops = std::to_array<int>({
  CAP_SYS_MODULE
});

constexpr auto caps_to_drop = std::to_array<int>({
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

}

/*
 * apply_capability_hardening()
 * 从环境边界集中移除危险的 capabilities 以缩减容器的攻击面，
 * 并在当前进程中同步丢弃，以限制在 execve 之前的提权活动。
 */
void apply_capability_hardening(const int privileged_mask) {
  if (privileged_mask & PRIV_NOCAPS) {
    log_info("[SEC] 已激活 privileged=nocaps: 跳过 Capabilities 裁剪。");
    return;
  }

  // 获取当前进程的 Capabilities 集合
  __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
  __user_cap_data_struct data[2] = {};

  if (syscall(SYS_capget, &hdr, data) < 0) {
    log_warn("[SEC] 无法获取当前进程 Capabilities: {}", strerror(errno));
    return;
  }

  // 定义泛型 Lambda 来处理任意容器的 Capability 丢弃逻辑
  auto drop_caps = [&](const auto &caps) -> int {
    int dropped_count = 0;
    for (const int cap : caps) {
      // 1. 从 Bounding Set (边界集) 中丢弃，这会影响后续的 execve 授权上限
      if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
        if (errno != EINVAL) {
          log_warn("[SEC] 无法移除边界 Cap {}: {}", cap, 
                   std::system_category().message(errno));
        }
      } else {
        dropped_count++;
      }

      // 2. 【修复 #2】同步从当前进程的 Effective, Permitted 和 Inheritable 集合中抹除
      // 因为如果不这么做，当前进程仍持有这些能力，安全性等同于没做
      if (cap >= 0 && cap < 64) {
        const int idx = cap >> 5;     // cap / 32
        const uint32_t mask = ~(1U << (cap & 31)); // ~(1 << (cap % 32))
        data[idx].effective   &= mask;
        data[idx].permitted   &= mask;
        data[idx].inheritable &= mask;
      }
    }
    return dropped_count;
  };

  // 3. 复用逻辑，累加结果
  int total_dropped = drop_caps(universal_drops) + drop_caps(caps_to_drop);

  // 4. 应用修改回内核，让能力剥夺立刻针对当前进程上下文生效
  if (syscall(SYS_capset, &hdr, data) < 0) {
    log_warn("[SEC] 无法应用 Capabilities 裁剪策略 (capset): {}", strerror(errno));
  }

  log_info("[SEC] 已完成内核权限边界裁剪 (共移除了 {} 个 Cap)。", total_dropped);
}

}
