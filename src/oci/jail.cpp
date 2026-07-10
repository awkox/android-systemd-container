#include "asc.h"

/* 必须屏蔽的路径 - 无论在何种模式下，容器都不应访问 */
static const char *universal_masks[] = {
  "/proc/sysrq-trigger",
  "/proc/kcore",
  "/proc/timer_list",
  nullptr
};

/* 必须使用 /dev/null 覆盖以屏蔽读取的路径 */
static const char *universal_nullify[] = {
  "/proc/partitions",
  nullptr
};

/* 
 * 屏蔽内核日志路径，并使用 FIFO 代替 /dev/null:
 * rsyslogd 等服务如果读 /dev/null 遇到 EOF 会导致 100% CPU 死循环。
 * 绑定一个拥有持久写入者的 FIFO 可以让读操作无限阻塞，
 * 既防止了死循环，又成功阻断了宿主机的内核日志泄漏。
 */
static const char *kmsg_block_paths[] = {
  "/dev/kmsg",
  "/proc/kmsg",
  nullptr
};

/* 标准模式下的只读路径 - 允许读取，禁止修改。
 * 覆盖了敏感的 proc 子树和危险的 sys 接口。 */
static const char *standard_ro[] = {
  "/proc/irq",
  "/sys/firmware",
  "/sys/kernel/security",
  "/sys/kernel/debug",
  "/sys/kernel/tracing",
  "/sys/block",
  nullptr
};

/* 
 * 故意排除了 /proc/sys/net: 在 host 模式下，这是破坏宿主机网络的可怕途径。
 * 但由于我们在 none 模式下隔离了网络，所以在这里打开安全的通道。
 */
static const char *rw_holes[] = {
  "/proc/sys/kernel/hostname",
  "/proc/sys/kernel/domainname",
  nullptr
};

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
 * 使用持久的 FIFO 写入者来阻塞读取请求。
 */
static void block_read_path(const char *path) {
  if (!fs::exists(path))
    return;

  fs::path fifo_path = tmp_dir / std::format(".asc-kmsg-fifo-{}", getpid());
  fs::remove(fifo_path);
  if (mkfifo(fifo_path.c_str(), 0600) < 0)
    return;

  /* Fork 出子进程以保持 FIFO 的写端打开。
   * 子进程无任何实际逻辑 — 只是休眠以维持文件描述符存活。 */
  const pid_t child = fork();
  if (child == 0) {
    const int wfd = open(fifo_path.c_str(), O_WRONLY);
    if (wfd >= 0)
      pause();
    _exit(0);
  }

  if (child > 0)
    mount(fifo_path.c_str(), path, nullptr, MS_BIND, nullptr);

  fs::remove(fifo_path);
}

/*
 * apply_jail_mask()
 *
 * 通过绑定自身并重新挂载为只读来保护敏感内核接口。
 * 这极大地减少了容器的攻击面，并防止其通过 /proc 和 /sys 操作宿主机。
 */
void apply_jail_mask(const int privileged_mask) {
  if (privileged_mask & PRIV_NOMASK) {
    log_info(
        "[SEC] 已激活 privileged=nomask: 跳过 /proc 与 /sys 的 Jail 路径保护。");
    return;
  }

  for (int i = 0; universal_masks[i]; i++) {
    mask_path(universal_masks[i]);
  }

  for (int i = 0; universal_nullify[i]; i++) {
    nullify_path(universal_nullify[i]);
  }

  for (int i = 0; kmsg_block_paths[i]; i++) {
    block_read_path(kmsg_block_paths[i]);
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

    for (int i = 0; rw_holes[i]; i++) {
      if (!fs::exists(rw_holes[i]))
        continue;
      if (mount(rw_holes[i], rw_holes[i], nullptr, MS_BIND, nullptr) < 0) {
        log_warn("[SEC] 无法将安全挂载洞 %s 绑定: %s", rw_holes[i],
                 strerror(errno));
        continue;
      }
      if (mount(rw_holes[i], rw_holes[i], nullptr,
                MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                nullptr) < 0)
        log_warn("[SEC] 无法重新挂载安全挂载洞 %s: %s", rw_holes[i],
                 strerror(errno));
    }
    log_info("[SEC] 已开启 /proc/sys 隔离豁免洞 (保证 hostname/domainname 修改可用)。");
  }

  for (int i = 0; standard_ro[i]; i++) {
    mask_path(standard_ro[i]);
  }

  log_info("[SEC] Jail 沙盒挂载限制已启用 (加固 /proc 与 /sys)。");
}