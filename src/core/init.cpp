#include "asc.h"

void internal_boot(cfg_t *cfg) {
  /* 定义所有的局部变量以避免 C++ 的 goto 跳跃错误 */
  pid_t existing_pid = 0;
  bool dir_creation_failed = false;
  const char *dirs_to_create[] = {".old_root", "proc", "sys", "run", "tmp"};
  bool used_ms_move = false;
  char *init_bin = nullptr;
  char *init_args[16];
  int argc = 0;
  struct statfs _cgsfs;

  /* 防御性检查：确保配置有效 */
  if (!cfg) {
    log_error("internal_boot 收到 NULL 空配置。");
    return;
  }

  /* 在隔离挂载命名空间 / 执行 pivot_root 之前，预先打开容器日志文件。
   * 这个文件描述符将在挂载命名空间变更中存活，确保能够捕获所有的底层日志。 */
  open_container_log(cfg);

  /* 对于启用网络隔离的情况：在隔离的网络命名空间中启动 loopback 回环网卡 */
  if (cfg->conf.isolation_network) {
    auto_free nl_ctx_t *nlctx = nl_open();
    if (nlctx) {
      nl_link_up(nlctx, "lo");
      close(nlctx->fd);
      log_info("[NET] 隔离网络命名空间：loopback 已启动");
    }
  }

  /* 0. 引导防护：确保名称存在且唯一。
   * 这是一个关键的安全检查，防止无名或冲突的容器被意外引导。 */
  if (!cfg->conf.container_name[0]) {
    log_error("严重错误：引导终止 — 容器名称为空。");
    goto boot_fail;
  }

  if (is_container_running(cfg->conf.uuid, &existing_pid)) {
    if (existing_pid != getpid()) {
      log_error(
          "严重错误：引导终止 — 名称 '%s' 已被 PID %d 占用。",
          cfg->conf.container_name, existing_pid);
      goto boot_fail;
    }
  }

  /* 1. 隔离挂载命名空间 */
  if (unshare(CLONE_NEWNS) < 0) {
    log_error("无法隔离挂载命名空间 (unshare): %s", strerror(errno));
    goto boot_fail;
  }

  /* 2. 将所有挂载转为私有模式 (MS_PRIVATE)，防止泄漏到宿主机。 */
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    log_error("无法将根目录挂载点设为 private: %s", strerror(errno));
    goto boot_fail;
  }

  /* 3. 在容器命名空间内设置易失性 Overlay 叠加层。 */
  if (cfg->conf.volatile_mode) {
    if (setup_volatile_overlay(cfg) < 0) {
      log_error("无法建立易失模式叠加层 (Overlay)。");
      goto boot_fail;
    }
  }

  /* 4. 将 rootfs 绑定挂载到其自身 (这是内核 pivot_root 调用的强制要求) */
  if (mount(cfg->conf.img_mount_point, cfg->conf.img_mount_point, nullptr,
            MS_BIND | MS_REC, nullptr) < 0) {
    log_error("无法执行自我绑定挂载: %s", strerror(errno));
    goto boot_fail;
  }

  /* 5. 设置工作目录为 rootfs */
  if (chdir(cfg->conf.img_mount_point) < 0) {
    log_error("无法 chdir 到 '%s': %s", cfg->conf.img_mount_point,
              strerror(errno));
    goto boot_fail;
  }

  /* 6. 从 /run/.boot-uuid 读取 UUID */
  if (cfg->conf.uuid[0] == '\0') {
    read_file("run/.boot-uuid", cfg->conf.uuid, sizeof(cfg->conf.uuid));
  }
  unlink("run/.boot-uuid");

  /* 7. 预创建标准的系统目录结构 */
  for (size_t i = 0; i < ARRAY_SIZE(dirs_to_create); i++) {
    if (mkdir(dirs_to_create[i], 0755) < 0 && errno != EEXIST) {
      log_error("无法创建目录 '%s': %s", dirs_to_create[i],
                strerror(errno));
      if (strcmp(dirs_to_create[i], ".old_root") == 0) {
        dir_creation_failed = true;
      }
    }
  }
  if (dir_creation_failed) {
    log_error("无法创建关键目录 .old_root");
    goto boot_fail;
  }

  /* 8. 配置 /dev (设备节点，或 devtmpfs) */
  if (setup_dev(".", cfg->conf.hw_access, cfg->conf.gpu_mode, cfg->conf.privileged_mask) < 0) {
    log_error("设置 /dev 环境失败。");
    goto boot_fail;
  }

  /* 9. 日志输出硬件访问模式状态 */
  if (!cfg->rt.reboot_cycle) {
    if (cfg->conf.hw_access)
      log_info("正在配置硬件完全直通环境...");
    else if (cfg->conf.gpu_mode)
      log_info("正在配置 GPU 加速直通环境...");
    else
      log_info("硬件直通已禁用：使用隔离的 tmpfs 伪终端...");
  }

  /* 10. 挂载虚拟文件系统 (proc, sys) */
  if (domount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 procfs 失败: %s", strerror(errno));
    goto boot_fail;
  }

  if (domount("sysfs", "sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
    log_error("挂载 sysfs 失败: %s", strerror(errno));
    goto boot_fail;
  }

  mkdir_p("sys/fs/cgroup", 0755);

  /* 系统级 sysfs 漏洞屏蔽策略 */
  if (cfg->conf.hw_access && cfg->rt.foreground) {
    auto_closedir DIR *d = opendir("sys");
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.')
          continue;

        char subpath[PATH_MAX];
        snprintf(subpath, sizeof(subpath), "sys/%s", de->d_name);

        struct stat st;
        if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
          if (mount(subpath, subpath, nullptr, MS_BIND | MS_REC, nullptr) < 0) {
          }
        }
      }
    }
  } else if (!cfg->conf.hw_access) {
    if (mkdir("sys/devices", 0755) < 0 && errno != EEXIST) {
    }
    if (mkdir("sys/devices/virtual", 0755) < 0 && errno != EEXIST) {
    }
    if (mkdir("sys/devices/virtual/net", 0755) < 0 && errno != EEXIST) {
    }
    if (mount("sys/devices/virtual/net", "sys/devices/virtual/net", nullptr,
              MS_BIND | MS_REC, nullptr) < 0) {
      log_warn("无法绑定挂载网络设备路径 (网络功能可能受限)");
    }
  }

  if (!cfg->conf.hw_access || cfg->rt.foreground) {
    if (mount(nullptr, "sys", nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) < 0) {
      log_warn("无法将 /sys 重新挂载为只读模式: %s", strerror(errno));
    }
  }

  /* 11. 在锁定 /sys 之后设置 Cgroups */
  if (setup_cgroups(cfg->conf.force_cgroupv1) < 0) {
    log_error("容器 Cgroups 配置失败。");
    goto boot_fail;
  }

  if (domount("tmpfs", "run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755") < 0) {
    log_error("挂载 /run (tmpfs) 失败: %s", strerror(errno));
    goto boot_fail;
  }

  if (domount("tmpfs", "tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777") < 0)
    log_warn("挂载 /tmp (tmpfs) 失败: %s", strerror(errno));

  /* 14. 在 pivot_root 前绑定挂载控制台 */
  if (mount(cfg->rt.console.name, "dev/console", nullptr, MS_BIND, nullptr) < 0)
    log_warn("无法绑定挂载 Console '%s': %s", cfg->rt.console.name,
             strerror(errno));

  /* 15. 执行根目录无缝切换 (pivot_root) */
  if (is_ramfs("/")) {
    log_info("检测到 rootfs/ramfs 宿主机 - 自动回退至 MS_MOVE + chroot 机制");
    used_ms_move = true;
    if (mount(".", "/", nullptr, MS_MOVE, nullptr) < 0) {
      log_error("MS_MOVE 挂载移动失败: %s", strerror(errno));
      goto boot_fail;
    }
    if (chroot(".") < 0) {
      log_error("MS_MOVE 后的 chroot 失败: %s", strerror(errno));
      goto boot_fail;
    }
  } else if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
    log_error("pivot_root 系统调用失败: %s", strerror(errno));
    goto boot_fail;
  }

  if (chdir("/") < 0) {
    log_error("pivot_root 后的 chdir(\"/\") 失败: %s", strerror(errno));
    goto boot_fail;
  }

  /* 应用延迟的挂载传播设置 */
  if (cfg->conf.privileged_mask & PRIV_SHARED) {
    if (mount(nullptr, "/", nullptr, MS_REC | MS_SHARED, nullptr) < 0) {
      log_warn("[SEC] 应用 MS_SHARED 挂载传播模式失败: %s",
               strerror(errno));
    } else {
      log_info("[SEC] 根目录挂载传播已设置为 SHARED.");
    }
  }

  /* 16. 设置 devpts */
  setup_devpts(cfg->conf.hw_access);

  /* 在 pivot_root 后应用监狱掩码保护 */
  apply_jail_mask(cfg->conf.hw_access, cfg->conf.privileged_mask);

  /* 16b. 资源可见性虚拟化 */
  if (is_mountpoint("/proc")) {
    if (virtualize_init(cfg) < 0)
      log_warn("[VIRT] 虚拟化资源初始化失败，将以无虚拟化状态继续运行。");
  } else {
    log_warn("[VIRT] /proc 尚未挂载，跳过资源虚拟化阶段。");
  }

  if (sethostname("(none)", 6) < 0) {
    log_warn("重置主机名失败: %s", strerror(errno));
  }

  if (!cfg->rt.reboot_cycle) {
    log_info("正在引导容器 '%s' (使用 init: %s)...", cfg->conf.container_name,
             cfg->conf.custom_init[0] ? cfg->conf.custom_init : DEFAULT_INIT);
  }

  /* 17. 写入容器标识，供 PID 发现 */
  mkdir(FORK_MARKER, 0755);
  if (cfg->conf.uuid[0] != '\0') {
    char uuid_path[PATH_MAX];
    snprintf(uuid_path, sizeof(uuid_path), FORK_MARKER "/%s", cfg->conf.uuid);
    write_file(uuid_path, "");
  }

  if (config_save(FORK_MARKER "/container.config", cfg) < 0) {
    log_warn("引导警告: 无法备份内部配置元数据");
  }

  write_file(FORK_MARKER "/name", cfg->conf.container_name);

  if (cfg->conf.img_mount_point[0])
    write_file(FORK_MARKER "/mount", cfg->conf.img_mount_point);

  write_file(FORK_MARKER "/version", PROJECT_VERSION);
  if (cfg->rt.foreground) {
    printf("\r\n(按下 CTRL+ALT+Q 以脱离前台并退出)\r\n");
    fflush(stdout);
  }
  printf("\r\n");
  fflush(stdout);

  /* 18. 清理卸载旧的根文件系统目录 */
  if (!used_ms_move) {
    if (umount2("/.old_root", MNT_DETACH) < 0)
      log_warn("卸载 /.old_root 失败: %s", strerror(errno));
    else
      rmdir("/.old_root");
  } else {
    rmdir("/.old_root");
  }

  /* 19. 清除环境变量并设置默认值 */
  clearenv();
  setenv("container", PROJECT_NAME, 1);
  if (cfg->conf.img_mount_point[0])
    setenv("RUNTIME_MOUNT_PATH", cfg->conf.img_mount_point, 1);

  /* 应用安全性防护：seccomp 策略与 capabilities 剔除 */
  seccomp_apply_minimal(cfg->conf.privileged_mask);
  android_seccomp_setup(cfg->conf.block_nested_ns &&
      !(cfg->conf.privileged_mask & PRIV_NOSEC),
      cfg->conf.privileged_mask);

  apply_capability_hardening(cfg->conf.hw_access, cfg->conf.privileged_mask);

  /* 20. 重定向标准输入输出至 /dev/console
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
        if (fchown(console_fd, 0, DEFAULT_TTY_GID) < 0) {
        }
        if (console_fd > 2)
          close(console_fd);
      }
    }
  }

  /* 21. 最终执行 INIT 程序 */
  init_bin = cfg->conf.custom_init[0] ? cfg->conf.custom_init : (char *)DEFAULT_INIT;
  init_args[argc++] = init_bin;

  if (statfs("/sys/fs/cgroup", &_cgsfs) == 0) {
    if (_cgsfs.f_type == CGROUP2_SUPER_MAGIC) {
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=1";
    } else {
      init_args[argc++] = (char *)"systemd.unified_cgroup_hierarchy=0";
      init_args[argc++] = (char *)"systemd.legacy_systemd_cgroup_controller=1";
    }
  }

  init_args[argc] = nullptr;

  if (execve(init_bin, init_args, environ) < 0) {
    log_error("执行 %s 失败: %s", init_bin, strerror(errno));
    log_die("容器引导崩溃。请检查 rootfs 是否损坏，且存在合法的 %s 二进制程序。",
            init_bin);
  }

boot_fail:
  close_container_log();
}