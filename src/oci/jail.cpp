#include "asc.h"

/* 必须屏蔽的路径 - 无论在何种模式下，容器都不应访问 */
static constexpr auto universal_masks = std::to_array<const char*>({
  "/proc/sysrq-trigger",
  "/proc/kcore",
  "/proc/timer_list",
});

/* 必须使用 /dev/null 覆盖以屏蔽读取的路径 */
static constexpr auto universal_nullify = std::to_array<const char*>({
  "/proc/partitions",
});

/* 标准模式下的只读路径 - 允许读取，禁止修改。
 * 覆盖了敏感的 proc 子树和危险的 sys 接口。 */
static constexpr auto standard_ro = std::to_array<const char*>({
  "/proc/irq",
  "/sys/firmware",
  "/sys/kernel/security",
  "/sys/kernel/debug",
  "/sys/kernel/tracing",
  "/sys/block",
});

/* 
 * 故意排除了 /proc/sys/net: 在 host 模式下，这是破坏宿主机网络的可怕途径。
 * 但由于我们在 none 模式下隔离了网络，所以在这里打开安全的通道。
 */
static constexpr auto rw_holes = std::to_array<const char*>({
  "/proc/sys/kernel/hostname",
  "/proc/sys/kernel/domainname",
});

/* 
 * 通过自我挂载并以只读方式重新挂载来屏蔽敏感路径。
 * 如果路径不存在则静默跳过。生成的挂载条目保留了父文件系统类型，
 * 例如 "proc on /proc/kcore type proc (ro)" - 与 LXC 的做法一致。 
 */
static void mask_path(const char *path) {
  if (!fs::exists(path))
    return;
  mount(path, path, nullptr, MS_BIND, nullptr);
  mount(path, path, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
}

/* 
 * 通过在其上绑定挂载 /dev/null 来作废一个路径。
 * 仅用于屏蔽内核日志等单纯阻塞写入不够的地方。
 */
static void nullify_path(const char *path) {
  if (!fs::exists(path))
    return;
  if (!fs::exists("/dev/null"))
    return;
  mount("/dev/null", path, nullptr, MS_BIND, nullptr);
}

/*
 * apply_jail_mask()
 *
 * 通过绑定自身并重新挂载为只读来保护敏感内核接口。
 * 这极大地减少了容器的攻击面，并防止其通过 /proc 和 /sys 操作宿主机。
 */
void apply_jail_mask(const int privileged_mask) {
  if (privileged_mask & PRIV_NOMASK) {
    log_info("[SEC] 已激活 privileged=nomask: 跳过 /proc 与 /sys 的 Jail 路径保护。");
    return;
  }

  for (const auto path : universal_masks) {
    mask_path(path);
  }

  for (const auto path : universal_nullify) {
    nullify_path(path);
  }

  /*
   * 大规模 /proc/sys 锁定 - 无论是在标准模式还是硬件模式均适用。
   */
  {
    if (fs::exists("/proc/sys")) {
      mount("/proc/sys", "/proc/sys", nullptr, MS_BIND, nullptr);
      mount("/proc/sys", "/proc/sys", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY,
            nullptr);
      log_info("[SEC] /proc/sys 现已锁定为只读。");
    }

    for (const auto path : rw_holes) {
      if (!fs::exists(path))
        continue;
      if (mount(path, path, nullptr, MS_BIND, nullptr) < 0) {
        log_warn("[SEC] 无法将安全挂载洞 %s 绑定: %s", path, strerror(errno));
        continue;
      }
      if (mount(path, path, nullptr,
                MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                nullptr) < 0)
        log_warn("[SEC] 无法重新挂载安全挂载洞 %s: %s", path, strerror(errno));
    }
    log_info("[SEC] 已开启 /proc/sys 隔离豁免洞 (保证 hostname/domainname 修改可用)。");
  }

  for (const auto path : standard_ro) {
    mask_path(path);
  }

  log_info("[SEC] Jail 沙盒挂载限制已启用 (加固 /proc 与 /sys)。");
}