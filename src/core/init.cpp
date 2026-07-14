#include "asc.h"

static constexpr auto dirs_to_create = std::to_array<const char*>({
  ".old_root", "proc", "sys", "dev", "run", "tmp"
});

static constexpr auto proc_sys_rw_holes = std::to_array<const char*>({
  "proc/sys/kernel/hostname",
  "proc/sys/kernel/domainname",
});

static constexpr auto proc_universal_masks = std::to_array<const char*>({
  "proc/sysrq-trigger",
  "proc/kcore",
  "proc/timer_list",
  "proc/irq",
});

void internal_boot(cfg_t *cfg) {
  fs::path mount_point = mount_dir / cfg->rt.container_name;

  /* 在隔离挂载命名空间 / 执行 pivot_root 之前，预先打开容器日志文件。
   * 这个文件描述符将在挂载命名空间变更中存活，确保能够捕获所有的底层日志。 */
  open_container_log(cfg->rt.container_name);

  /* 1. 挂载传播隔离 */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    log_error("无法设置根目录挂载传播模式 (MS_PRIVATE): %s", strerror(errno));
    goto boot_fail;
  }

  // 2. 挂载镜像
  if (!cfg->conf.rootfs_img_path.empty()) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, mount_point) < 0) {
      log_error("无法挂载镜像: %s", strerror(errno));
      goto boot_fail;
    }
  }

  /* 3. 设置工作目录为 rootfs */
  if (chdir(mount_point.c_str()) < 0) {
    log_error("无法 chdir 到 '%s': %s", mount_point.c_str(), strerror(errno));
    goto boot_fail;
  }

  /* 4. 预创建标准的系统目录结构 */
  for (const auto dir : dirs_to_create) {
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
      log_error("无法创建目录 '%s': %s", dir, strerror(errno));
      goto boot_fail;
    }
  }

  // 5. proc
  {
    if (mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
      log_error("挂载 procfs 失败: %s", strerror(errno));
      goto boot_fail;
    }

    if (!(cfg->conf.privileged_mask & PRIV_NOMASK)) {
      for (const auto path : proc_universal_masks) {
        mask_path(path);
      }
    }

    if (mask_path("proc/sys") < 0) {
      log_error("屏蔽/proc/sys失败: %s", strerror(errno));
      goto boot_fail;
    }

    for (const auto path : proc_sys_rw_holes) {
      if (!fs::exists(path))
        continue;
      if (mount(path, path, nullptr, MS_BIND, nullptr) < 0) {
        log_warn("[SEC] 无法将安全挂载洞 %s 绑定: %s", path, strerror(errno));
        continue;
      }
      if (mount(path, path, nullptr, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0)
        log_warn("[SEC] 无法重新挂载安全挂载洞 %s: %s", path, strerror(errno));
    }
  }

  // 6. sys
  if (mount("sysfs", "sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 sysfs 失败: %s", strerror(errno));
    goto boot_fail;
  }

  // 7. dev
  {
    if (mount("none", "dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "size=8M,mode=755") < 0)
      goto boot_fail;

    if (setup_dev() < 0) {
      log_error("设置 /dev 环境失败。");
      goto boot_fail;
    }

    if (setup_devpts() < 0) {
      goto boot_fail;
    }

    /* 在 pivot_root 前绑定挂载控制台 */
    if (mount(cfg->rt.console.name.c_str(), "dev/console", nullptr, MS_BIND, nullptr) < 0)
      log_warn("无法绑定挂载 Console '%s': %s", cfg->rt.console.name.c_str(), strerror(errno));
  }

  /* 8. 执行根目录无缝切换 (pivot_root) */
  {
    if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
      log_error("pivot_root 系统调用失败: %s", strerror(errno));
      goto boot_fail;
    }

    if (chdir("/") < 0) {
      log_error("pivot_root 后的 chdir(\"/\") 失败: %s", strerror(errno));
      goto boot_fail;
    }

    /* 清理卸载旧的根文件系统目录 */
    if (umount2(".old_root", MNT_DETACH) < 0)
      log_warn("卸载 .old_root 失败: %s", strerror(errno));
    else
      rmdir(".old_root");
  }

  // 目前处于根目录

  /* 10. 符合 systemd 的要求：在调用 systemd 作为 PID 1 之前，容器的挂载层级必须是 MS_SHARED。
   * 如果之前是 MS_PRIVATE（双向隔离），这里会创建一个独立的共享 peer group 供容器内使用。
   */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_SHARED, nullptr) < 0) {
    log_error("无法将根目录重新挂载为 MS_SHARED (systemd 依赖): %s", strerror(errno));
    goto boot_fail;
  }

  // 11. hostname
  if (sethostname("(none)", 6) < 0) {
    log_warn("重置主机名失败: %s", strerror(errno));
  }

  /* 12 应用安全性防护：seccomp 策略与 capabilities 剔除 */
  if (seccomp_apply_minimal(cfg->conf.privileged_mask) < 0) {
    log_die("Seccomp 应用失败，拒绝启动不安全的容器");
  }
  // 13
  android_seccomp_setup(cfg->conf.block_nested_ns &&
      !(cfg->conf.privileged_mask & PRIV_NOSEC),
      cfg->conf.privileged_mask);

  // 14
  apply_capability_hardening(cfg->conf.privileged_mask);

  /* 15. 重定向标准输入输出至 /dev/console
   * 使用局部代码块，防止 console_fd 触发 C++ 的 goto 跳跃错误 */
  {
    const int console_fd = open("dev/console", O_RDWR);
    if (console_fd >= 0) {
      if (terminal_set_stdfds(console_fd) < 0) {
        log_warn("无法将标准 I/O 重定向到 /dev/console");
        close(console_fd);
      } else {
        terminal_make_controlling(console_fd);

        struct winsize ws;
        if (ioctl(console_fd, TIOCGWINSZ, &ws) == 0
              && ws.ws_col == 0
              && ws.ws_row == 0) {
          ws.ws_row = 24;
          ws.ws_col = 80;
          ioctl(console_fd, TIOCSWINSZ, &ws);
        }

        fchmod(console_fd, 0620);
        if (fchown(console_fd, 0, 5) < 0) {}
        if (console_fd > 2)
          close(console_fd);
      }
    }
  }

  if (cfg->rt.foreground) {
    printf("\r\n(按下 CTRL+ALT+Q 以脱离前台并退出)\r\n");
  }
  printf("\r\n");
  fflush(stdout);

  // 17
  {
    const char *init_bin = cfg->conf.custom_init.empty() ? DEFAULT_INIT : cfg->conf.custom_init.c_str();
    const char *init_args[] = {init_bin, "systemd.unified_cgroup_hierarchy=1", nullptr};
    const char *environment[] = {"container=asc", nullptr};

    if (execve(init_bin, const_cast<char *const *>(init_args), const_cast<char *const *>(environment)) < 0) {
      log_error("执行 %s 失败: %s", init_bin, strerror(errno));
      log_die("容器引导崩溃。请检查 rootfs 是否损坏，且存在合法的 %s 二进制程序。", init_bin);
    }
  }

boot_fail:
  close_container_log();
}