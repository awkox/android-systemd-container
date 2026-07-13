#include "asc.h"

void internal_boot(cfg_t *cfg) {
  /* 定义所有的局部变量以避免 C++ 的 goto 跳跃错误 */
  bool dir_creation_failed = false;
  static constexpr auto dirs_to_create = std::to_array<const char*>({
    ".old_root", "proc", "sys", "run", "tmp"
  });
  fs::path mount_point = mount_dir / cfg->rt.container_name;

  /* 在隔离挂载命名空间 / 执行 pivot_root 之前，预先打开容器日志文件。
   * 这个文件描述符将在挂载命名空间变更中存活，确保能够捕获所有的底层日志。 */
  open_container_log(cfg->rt.container_name);

  /* 对于启用网络隔离的情况：在隔离的网络命名空间中启动 loopback 回环网卡 */
  if (cfg->conf.isolation_network) {
    auto_free nl_ctx_t *nlctx = nl_open();
    if (nlctx) {
      nl_link_up(nlctx, "lo");
      close(nlctx->fd);
      log_info("[NET] 隔离网络命名空间：loopback 已启动");
    }
  }

  /* 2. 挂载传播隔离 */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    log_error("无法设置根目录挂载传播模式 (MS_PRIVATE): %s", strerror(errno));
    goto boot_fail;
  }

  if (!cfg->conf.rootfs_img_path.empty()) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, mount_point) < 0) {
      log_error("无法挂载镜像: %s", strerror(errno));
      goto boot_fail;
    }
  }
  /* 3. 将 rootfs 绑定挂载到其自身 (这是内核 pivot_root 调用的强制要求) */
  if (mount(mount_point.c_str(), mount_point.c_str(), nullptr,
            MS_BIND | MS_REC, nullptr) < 0) {
    log_error("无法执行自我绑定挂载: %s", strerror(errno));
    goto boot_fail;
  }

  /* 4. 设置工作目录为 rootfs */
  if (chdir(mount_point.c_str()) < 0) {
    log_error("无法 chdir 到 '%s': %s", mount_point.c_str(),
              strerror(errno));
    goto boot_fail;
  }

  /* 5. 预创建标准的系统目录结构 */
  for (const auto dir : dirs_to_create) {
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
      log_error("无法创建目录 '%s': %s", dir, strerror(errno));
      if (strcmp(dir, ".old_root") == 0) {
        dir_creation_failed = true;
      }
    }
  }
  if (dir_creation_failed) {
    log_error("无法创建关键目录 .old_root");
    goto boot_fail;
  }

  /* 6. 配置 /dev (设备节点，或 devtmpfs) */
  if (setup_dev() < 0) {
    log_error("设置 /dev 环境失败。");
    goto boot_fail;
  }

  /* 7. 挂载虚拟文件系统 (proc, sys) */
  if (domount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 procfs 失败: %s", strerror(errno));
    goto boot_fail;
  }

  if (domount("sysfs", "sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 sysfs 失败: %s", strerror(errno));
    goto boot_fail;
  }

  create_directories_with_permission("sys/fs/cgroup");

  /* 系统级 sysfs 漏洞屏蔽策略 */
  create_directories_with_permission("sys/devices/virtual/net");
  if (mount("sys/devices/virtual/net", "sys/devices/virtual/net", nullptr,
            MS_BIND | MS_REC, nullptr) < 0) {
    log_warn("无法绑定挂载网络设备路径 (网络功能可能受限)");
  }

  /* 必须先将 sys 转换为 bind 挂载，切断与全局 superblock 属性的强绑定 */
  mount("sys", "sys", nullptr, MS_BIND | MS_REC, nullptr);

  /* 在 remount 时必须带上 MS_BIND 标志，明确告诉内核只修改当前挂载点的属性 */
  if (mount(nullptr, "sys", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_warn("无法将 /sys 重新挂载为只读模式: %s", strerror(errno));
  }

  /* 9. 在 pivot_root 前绑定挂载控制台 */
  if (mount(cfg->rt.console.name.c_str(), "dev/console", nullptr, MS_BIND, nullptr) < 0)
    log_warn("无法绑定挂载 Console '%s': %s", cfg->rt.console.name.c_str(),
             strerror(errno));

  /* 10. 执行根目录无缝切换 (pivot_root) */
  if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
    log_error("pivot_root 系统调用失败: %s", strerror(errno));
    goto boot_fail;
  }

  if (chdir("/") < 0) {
    log_error("pivot_root 后的 chdir(\"/\") 失败: %s", strerror(errno));
    goto boot_fail;
  }

  // 目前处于根目录

  /* 符合 systemd 的要求：在调用 systemd 作为 PID 1 之前，容器的挂载层级必须是 MS_SHARED。
   * 如果之前是 MS_PRIVATE（双向隔离），这里会创建一个独立的共享 peer group 供容器内使用。
   * 如果之前是 MS_SHARED（双向传播），这里会再次确认共享状态。 */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_SHARED, nullptr) < 0) {
    log_error("无法将根目录重新挂载为 MS_SHARED (systemd 依赖): %s", strerror(errno));
    goto boot_fail;
  }

  /* 11. 设置 devpts */
  setup_devpts();

  /* 在 pivot_root 后应用监狱掩码保护 */
  apply_jail_mask(cfg->conf.privileged_mask);

  if (sethostname("(none)", 6) < 0) {
    log_warn("重置主机名失败: %s", strerror(errno));
  }

  if (cfg->rt.foreground) {
    printf("\r\n(按下 CTRL+ALT+Q 以脱离前台并退出)\r\n");
  }
  printf("\r\n");
  fflush(stdout);

  /* 12. 清理卸载旧的根文件系统目录 */
  if (umount2("/.old_root", MNT_DETACH) < 0)
    log_warn("卸载 /.old_root 失败: %s", strerror(errno));
  else
    fs::remove("/.old_root");

  /* 13. 清除环境变量并设置默认值 */
  clearenv();
  setenv("container", PROJECT_NAME, 1);

  /* 应用安全性防护：seccomp 策略与 capabilities 剔除 */
  if (seccomp_apply_minimal(cfg->conf.privileged_mask) < 0) {
    log_die("Seccomp 应用失败，拒绝启动不安全的容器");
  }
  android_seccomp_setup(cfg->conf.block_nested_ns &&
      !(cfg->conf.privileged_mask & PRIV_NOSEC),
      cfg->conf.privileged_mask);

  apply_capability_hardening(cfg->conf.privileged_mask);

  /* 14. 重定向标准输入输出至 /dev/console
   * 使用局部代码块，防止 console_fd 触发 C++ 的 goto 跳跃错误 */
  {
    const int console_fd = open("/dev/console", O_RDWR);
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
        if (fchown(console_fd, 0, 5) < 0) {
        }
        if (console_fd > 2)
          close(console_fd);
      }
    }
  }

  {
    const char *init_bin = cfg->conf.custom_init.empty() ? DEFAULT_INIT : cfg->conf.custom_init.c_str();
    const char *init_args[] = {init_bin, "systemd.unified_cgroup_hierarchy=1", nullptr};

    if (execve(init_bin, const_cast<char *const *>(init_args), environ) < 0) {
      log_error("执行 %s 失败: %s", init_bin, strerror(errno));
      log_die("容器引导崩溃。请检查 rootfs 是否损坏，且存在合法的 %s 二进制程序。",
              init_bin);
    }
  }

boot_fail:
  close_container_log();
}