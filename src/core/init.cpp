#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <utmp.h>
#include <stdio.h>
#include <cerrno>
#include <cstring>
#include <array>
#include <filesystem>
#include <string>

#include "core.h"
#include "utils/log.h"
#include "utils/path.h"
#include "platform/mount.h"
#include "platform/devices.h"
#include "oci.h"
#include "common.h"

namespace asc::core {

namespace {

constexpr auto dirs_to_create = std::to_array<const char*>({
  ".old_root", "proc", "sys", "dev", "run", "tmp"
});

constexpr auto proc_sys_rw_holes = std::to_array<const char*>({
  "proc/sys/kernel/hostname",
  "proc/sys/kernel/domainname",
});

constexpr auto proc_universal_masks = std::to_array<const char*>({
  "proc/sysrq-trigger",
  "proc/kcore",
  "proc/timer_list",
  "proc/irq",
});

constexpr const char* DEFAULT_INIT = "/sbin/init";

/* 1. 基础挂载隔离与 Rootfs 挂载 */
bool setup_mount_isolation_and_rootfs(asc::rt &rt) {
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    log_error("无法设置根目录挂载传播模式 (MS_PRIVATE): {}", strerror(errno));
    return false;
  }

  if (!rt.cfg.rootfs_img_path.empty()) {
    log_info("[BOOT] 准备挂载 Rootfs 镜像...");
    std::filesystem::path mount_point = mount_dir / rt.container_name;
    if (mount_rootfs_img(rt.cfg.rootfs_img_path, mount_point) < 0) {
      log_error("无法挂载镜像: {}", strerror(errno));
      return false;
    }
    if (chdir(mount_point.c_str()) < 0) {
      log_error("无法 chdir 到 '{}': {}", mount_point.c_str(), strerror(errno));
      return false;
    }
  }
  return true;
}

/* 2. Procfs 挂载及安全加固 */
bool setup_procfs(const asc::conf &cfg) {
  if (mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 procfs 失败: {}", strerror(errno));
    return false;
  }

  if (!(cfg.privileged_mask & PRIV_NOMASK)) {
    for (const auto path : proc_universal_masks) mask_path(path);
  }

  if (mask_path("proc/sys") < 0) {
    log_error("屏蔽 /proc/sys 失败: {}", strerror(errno));
    return false;
  }

  for (const auto path : proc_sys_rw_holes) {
    if (!std::filesystem::exists(path)) continue;
    if (mount(path, path, nullptr, MS_BIND, nullptr) < 0) {
      log_warn("[SEC] 无法将安全挂载洞 {} 绑定: {}", path, strerror(errno));
      continue;
    }
    if (mount(path, path, nullptr, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0)
      log_warn("[SEC] 无法重新挂载安全挂载洞 {}: {}", path, strerror(errno));
  }
  return true;
}

/* 3. 核心虚拟文件系统建立 */
bool setup_virtual_filesystems(asc::rt &rt) {
  log_info("[BOOT] 正在挂载并配置虚拟文件系统 (proc, sys, dev)...");

  for (const auto dir : dirs_to_create) {
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
      log_error("无法创建目录 '{}': {}", dir, strerror(errno));
      return false;
    }
  }

  if (!setup_procfs(rt.cfg)) return false;

  if (mount("sysfs", "sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 sysfs 失败: {}", strerror(errno));
    return false;
  }

  if (mount("none", "dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "size=8M,mode=755") < 0) return false;
  if (setup_dev() < 0) {
    log_error("设置 /dev 环境失败。");
    return false;
  }
  if (setup_devpts() < 0) return false;

  if (mount(rt.console.name.c_str(), "dev/console", nullptr, MS_BIND, nullptr) < 0)
    log_warn("无法绑定挂载 Console '{}': {}", rt.console.name.c_str(), strerror(errno));

  return true;
}

/* 4. 执行 pivot_root 切换根目录 */
bool execute_pivot_root() {
  log_info("[BOOT] 正在执行 pivot_root (无缝切换系统根目录)...");

  if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
    log_error("pivot_root 系统调用失败: {}", strerror(errno));
    return false;
  }
  if (chdir("/") < 0) {
    log_error("pivot_root 后的 chdir(\"/\") 失败: {}", strerror(errno));
    return false;
  }
  if (umount2(".old_root", MNT_DETACH) < 0) {
    log_error("卸载 .old_root 失败: {}", strerror(errno));
    return false;
  }
  rmdir(".old_root");
  return true;
}

/* 5. Systemd 依赖与网络环境调整 */
bool setup_system_environment() {
  if (mount(nullptr, "/", nullptr, MS_REC | MS_SHARED, nullptr) < 0) {
    log_error("无法将根目录重新挂载为 MS_SHARED: {}", strerror(errno));
    return false;
  }
  if (sethostname("(none)", 6) < 0) {
    log_warn("重置主机名失败: {}", strerror(errno));
  }
  return true;
}

/* 6. 标准输入输出挂载与终端绑定 */
void setup_console_stdio() {
  const int console_fd = open("dev/console", O_RDWR);
  if (console_fd < 0) return;

  winsize ws;
  if (ioctl(console_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col == 0 && ws.ws_row == 0) {
    ws.ws_row = 24;
    ws.ws_col = 80;
    ioctl(console_fd, TIOCSWINSZ, &ws);
  }
  
  fchmod(console_fd, 0620);
  if (fchown(console_fd, 0, 5) < 0) {}

  // 【核心优化】使用标准库 login_tty 替代所有的 dup2、setsid 和 TIOCSCTTY
  // 它甚至会自动帮你执行 close(console_fd)，如果它大于2的话！
  if (login_tty(console_fd) < 0) {
    log_warn("login_tty 失败，无法绑定终端: {}", strerror(errno));
  }
}

/* 7. 引导 PID 1 进程 */
void execute_init_process(asc::rt &rt) {
  const char *init_bin = rt.cfg.custom_init.empty() ? DEFAULT_INIT : rt.cfg.custom_init.c_str();
  const char *init_args[] = {init_bin, "systemd.unified_cgroup_hierarchy=1", nullptr};
  const char *environment[] = {"container=asc", nullptr};

  log_info("[BOOT] 容器引导环境搭建完毕，移交控制权至 PID 1 ({})...", init_bin);

  printf("\r\n");
  fflush(stdout);

  if (execve(init_bin, const_cast<char *const *>(init_args), const_cast<char *const *>(environment)) < 0) {
    log_error("执行 {} 失败: {}", init_bin, strerror(errno));
  }
}

}

void internal_boot(asc::rt &rt) {
  log_info("[BOOT] 正在初始化容器内部运行环境...");

  // 1. 挂载传播隔离与 Rootfs 挂载
  if (!setup_mount_isolation_and_rootfs(rt)) return;

  // 2. 构建 proc, sys, dev 虚拟文件系统
  if (!setup_virtual_filesystems(rt)) return;

  // 3. 切换根目录
  if (!execute_pivot_root()) return;

  // 4. 调整根目录标志与主机名
  if (!setup_system_environment()) return;

  // 5. 应用安全性防护
  log_info("[BOOT] 正在应用系统安全加固与沙箱隔离策略...");
  print_privileged_warning(rt.cfg.privileged_mask);
  if (asc::oci::seccomp_apply_minimal(rt.cfg.privileged_mask) < 0) {
    log_error("Seccomp 应用失败，拒绝启动不安全的容器");
    return;
  }
  asc::oci::android_seccomp_setup(rt.cfg.block_nested_ns, rt.cfg.privileged_mask);
  asc::oci::apply_capability_hardening(rt.cfg.privileged_mask);

  // 6. 绑定控制台输入输出
  setup_console_stdio();

  // 7. 脱离当前上下文，执行 init 进程
  execute_init_process(rt);
}

}
