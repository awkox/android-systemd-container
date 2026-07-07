#include "asc.h"

/* ---------------------------------------------------------------------------
 * 外部命令锁 - 仅用于 CLI 命令行工具独占控制
 *
 * 该锁仅代表一件事：当前有一个外部 CLI 命令正在管理此容器。
 * 只有 CLI 父进程能创建和释放锁。监控进程(monitor)对锁是只读的。
 * ---------------------------------------------------------------------------*/

/* 保存当前进程持有的锁 FD 和路径，解决进程内多次申请锁的重入问题 */
static int active_lock_fd = -1;
static char active_lock_path[PATH_MAX] = "";

/* 构建锁路径并进行防御性截断。精度：
 * 2048 (lock_dir) + 256 (name) + 5 (.lock) = 2309 < PATH_MAX (4096)
 * 这样可以防止格式截断警告，同时确保路径永远不会溢出。 */
static int get_lock_path(const char *name, char *buf, const size_t size) {
  if (!name || !buf || size == 0 || !validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));
  const int r =
      snprintf(buf, size, "%.2048s/%.256s.lock", get_lock_dir(), safe_name);
  return r > 0 && (size_t)r < size ? 0 : -1;
}

/* 创建外部命令锁 - 仅由 CLI 父进程调用。
 * 使用 POSIX 记录锁 (fcntl)，以便在进程崩溃时内核能自动清理。 */
static int acquire_external_lock(const char *name) {
  /* 重入支持：如果当前进程已经持有锁，直接返回成功 */
  if (active_lock_fd >= 0)
    return 0;

  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return -1;

  /* 获取写锁必须使用可写模式打开 */
  const int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  struct flock fl = {};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;

  /* 尝试非阻塞 POSIX 记录锁 */
  if (fcntl(fd, F_SETLK, &fl) == 0) {
    /* 获取成功。依然写入 PID，仅用于后续可能的纯文本 Debug */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(fd, 0) == 0) {
      write_all(fd, pid_str, strlen(pid_str));
    }
    
    /* 记录 FD，进程退出或关闭该 FD 时，内核会自动释放锁 */
    active_lock_fd = fd;
    safe_strncpy(active_lock_path, lock_path, sizeof(active_lock_path));
    return 0;
  }

  /* 锁被其他进程占用，向内核查询持有者的 PID 并打印 */
  if (errno == EACCES || errno == EAGAIN) {
    fl.l_type = F_WRLCK;
    if (fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK) {
      log_warn("无法获取锁: 当前已被进程 %d 持有", fl.l_pid);
    }
  }

  close(fd);
  return -1;
}

/* 释放外部命令锁 - 仅由 CLI 父进程调用。 */
static void release_external_lock(void) {
  if (active_lock_fd >= 0) {
    /* 
     * 在关闭 FD 前先 unlink，防止其他排队的进程获取到一个即将被删除的孤儿文件的锁。
     */
    if (active_lock_path[0]) {
      unlink(active_lock_path);
    }
    
    /* 原子操作：关闭 FD 的瞬间，内核释放关联的 POSIX 锁 */
    close(active_lock_fd);
    active_lock_fd = -1;
    active_lock_path[0] = '\0';
  }
}

/* 检查外部命令锁是否存在 - 仅供 monitor 调用 (只读模式)。 */
bool is_external_lock_active(const char *name) {
  char lock_path[PATH_MAX];
  if (get_lock_path(name, lock_path, sizeof(lock_path)) < 0)
    return false;

  auto_close const int fd = open(lock_path, O_RDONLY | O_CLOEXEC);
  return !(fd < 0);
}

void cleanup_container_resources(cfg_t *cfg, const bool force_cleanup) {
  /* 刷新文件系统缓冲区（如果强制清理则跳过，防止卡死） */
  if (!force_cleanup)
    sync();

  /* 1. 清理固件路径（仅限硬件直通模式；强制清理跳过） */
  if (!force_cleanup && cfg->conf.hw_access && cfg->conf.img_mount_point[0]) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 2. 处理易失性 Overlay 模式清理 (upper/work/merged)
   * 必须在卸载底层镜像挂载之前发生。 */
  if (cfg->conf.volatile_mode) {
    if (force_cleanup) {
      /* 强制模式：跳过同步，直接解除挂载 */
      char merged[PATH_MAX + 32];
      snprintf(merged, sizeof(merged), "%s/merged", cfg->rt.volatile_dir);
      umount2(merged, MNT_DETACH | MNT_FORCE);
      umount2(cfg->rt.volatile_dir, MNT_DETACH | MNT_FORCE);
      remove_recursive(cfg->rt.volatile_dir);
      cfg->rt.volatile_dir[0] = '\0';
    } else {
      cleanup_volatile_overlay(&cfg->rt);
    }
  }

  /* 4. 处理 rootfs 镜像卸载 */
  char mount_point[PATH_MAX] = "";
  if (cfg->conf.img_mount_point[0]) {
    safe_strncpy(mount_point, cfg->conf.img_mount_point, sizeof(mount_point));
  }

  if (mount_point[0]) {
    if (force_cleanup) {
      umount2(mount_point, MNT_DETACH | MNT_FORCE);
      rmdir(mount_point);
    } else {
      unmount_rootfs_img(mount_point, cfg->rt.foreground);
    }
  }

  /* Cgroup 子树清理：删除 /sys/fs/cgroup/asc/<name>/ 目录。 */
  cgroup_cleanup_container(cfg->conf.container_name);
}

bool is_valid_container_pid(const pid_t pid) {
  char path[PATH_MAX];

  /* 容器内必须存在 /run/asc 标识目录。 */
  if (build_proc_root_path(pid, FORK_MARKER, path, sizeof(path)) < 0)
    return false;
  if (access(path, F_OK) != 0)
    return false;

  /* 必须是其命名空间的 init 进程 (PID 1) */
  if (!is_container_init(pid))
    return false;

  return true;
}

int start_rootfs(cfg_t *cfg) {
  bool has_side_effects = false;
  bool lock_acquired = false;
  pid_t existing_pid = 0;
  int sync_pipe[2] = {-1, -1};
  pid_t monitor_pid = -1;
  char marker[PATH_MAX];
  bool booted = false;

  /* 0. 早期重启检测：检查之前停止命令留下的锁 */
  if (cfg->conf.container_name[0]) {
    char lock_path[PATH_MAX];
    if (get_lock_path(cfg->conf.container_name, lock_path, sizeof(lock_path)) == 0 &&
        access(lock_path, F_OK) == 0) {
      if (acquire_external_lock(cfg->conf.container_name) == 0) {
        lock_acquired = true;

        if (cfg->conf.img_mount_point[0] && is_mountpoint(cfg->conf.img_mount_point)) {
        } else {
          release_external_lock();
          lock_acquired = false;
        }
      }
    }
  }

  /* 1. 唯一性检查：防止同名容器多次启动 */
  if (!lock_acquired) {
    if (is_container_running(cfg->conf.uuid, &existing_pid)) {
      log_error("容器名称 '%s' 已被 PID %d 占用。",
                cfg->conf.container_name, existing_pid);
      goto cleanup;
    }
  }

  /* 2. 准备运行环境 */
  ensure_runtime();

  /* 0a. 将 rootfs 路径解析为绝对路径以防止符号链接攻击 */
  if (cfg->conf.rootfs_img_path[0]) {
    auto_free char *abs_path = resolve_path_arg(cfg->conf.rootfs_img_path);
    if (!abs_path || access(abs_path, F_OK) != 0) {
      log_error("无法解析 rootfs 镜像路径 '%s': %s",
                abs_path ? abs_path : cfg->conf.rootfs_img_path, strerror(errno));
      goto cleanup;
    }
    safe_strncpy(cfg->conf.rootfs_img_path, abs_path, sizeof(cfg->conf.rootfs_img_path));
  }

  /* 自动回退后台模式：如果请求前台但没有交互终端，则转入后台运行 */
  if (cfg->rt.foreground && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
    cfg->rt.foreground = 0;
    log_warn("无交互式终端 - 已禁用前台模式，转入后台运行。");
  }

  print_cgroup_status(cfg);

  has_side_effects = true;

  /* 2. 挂载 rootfs 镜像 */
  if (cfg->conf.rootfs_img_path[0] && !lock_acquired) {
    if (mount_rootfs_img(cfg->conf.rootfs_img_path, cfg->conf.img_mount_point,
                         sizeof(cfg->conf.img_mount_point), cfg->conf.container_name) < 0) {
      goto cleanup;
    }
  }

  /* 2a. 挂载后立即校验 init 二进制文件是否存在，防止空跑 */
  {
    char init_path[PATH_MAX * 2];
    char rootfs_norm[PATH_MAX];
    if (cfg->conf.img_mount_point[0])
      safe_strncpy(rootfs_norm, cfg->conf.img_mount_point, sizeof(rootfs_norm));
    else {
      log_error("未获取到 Rootfs 镜像挂载点。");
      return -1;
    }
    size_t rlen = strlen(rootfs_norm);
    if (rlen > 0 && rootfs_norm[rlen - 1] == '/')
      rootfs_norm[rlen - 1] = '\0';

    const char *init_bin =
        cfg->conf.custom_init[0] ? cfg->conf.custom_init : DEFAULT_INIT;
    snprintf(init_path, sizeof(init_path), "%.*s%s",
             (int)(sizeof(init_path) - strlen(init_bin) - 1), rootfs_norm,
             init_bin);
    struct stat st;
    if (lstat(init_path, &st) != 0) {
      log_error("未找到 Init 文件: %s", init_path);
      log_error("请确保 rootfs 路径正确且包含了 %s 可执行文件。",
                init_bin);
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
    if (!S_ISLNK(st.st_mode) && access(init_path, X_OK) != 0) {
      log_error("Init 文件没有可执行权限: %s", init_path);
      log_error("请确保为其赋予可执行权限 (chmod +x)。");
      unmount_rootfs_img(cfg->conf.img_mount_point, cfg->rt.foreground);
      return -1;
    }
  }

  /* 3. 易失模式 (Volatile) 的预检 */
  if (check_volatile_mode(&cfg->conf) < 0) {
    goto cleanup;
  }

  /* UUID 生成与持久化 */
  {
    char active_uuids[MAX_CONTAINERS][UUID_LEN + 1];
    int uuid_count = collect_active_uuids(active_uuids, MAX_CONTAINERS);
    bool need_new = cfg->conf.uuid[0] == '\0';
    if (!need_new) {
      for (int _i = 0; _i < uuid_count; _i++) {
        if (strcmp(cfg->conf.uuid, active_uuids[_i]) == 0) {
          need_new = true;
          break;
        }
      }
    }
    if (need_new)
      generate_uuid(cfg->conf.uuid, sizeof(cfg->conf.uuid));
  }

  if (cfg->rt.config_file[0]) {
    bool was_new = !cfg->rt.config_file_existed;
    if (config_save(cfg->rt.config_file, cfg) < 0) {
      log_error("无法持久化配置到 '%s': %s", cfg->rt.config_file,
                strerror(errno));
      goto cleanup;
    }
    if (was_new) {
      log_info("配置已成功持久化至 %s", cfg->rt.config_file);
    }
  }

  if (config_save_by_name(cfg->conf.container_name, cfg) < 0) {
    log_warn("无法将工作区镜像配置同步至 '%s': %s",
             cfg->conf.container_name, strerror(errno));
  }

  if (cfg->conf.volatile_mode) {
    snprintf(cfg->rt.volatile_dir, sizeof(cfg->rt.volatile_dir),
             "%s/" RUNTIME_VOLATILE_SUBDIR "/%s", get_runtime_dir(),
             cfg->conf.container_name);
  }

  /* 4. 分配容器交互所用的伪终端 (PTY) */
  if (cfg->conf.hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_add(fw_path);
  }

  fix_host_ptys();

  if (terminal_create(&cfg->rt.console) < 0) {
    log_error("无法分配容器控制台 (Console) PTY");
    goto cleanup;
  }

  /* 窗口尺寸同步 */
  if (isatty(STDIN_FILENO)) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(cfg->rt.console.master, TIOCSWINSZ, &ws);
  }

  /* 5. 创建用于同步的管道 */
  if (pipe(sync_pipe) < 0) {
    log_error("创建管道失败: %s", strerror(errno));
    goto cleanup;
  }

  fcntl(sync_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl(sync_pipe[1], F_SETFD, FD_CLOEXEC);

  clock_gettime(CLOCK_BOOTTIME, &cfg->rt.start_time);

  /* 7. Fork 出监控进程 (Monitor) */
  monitor_pid = fork();
  if (monitor_pid < 0) {
    close(sync_pipe[0]);
    close(sync_pipe[1]);
    log_error("fork(Monitor) 失败: %s", strerror(errno));
    goto cleanup;
  }

  if (monitor_pid == 0) {
    close(sync_pipe[0]);
    monitor_run(cfg, sync_pipe[1]);
    _exit(EXIT_FAILURE);
  }

  /* ==== 父进程流程 ==== */
  close(sync_pipe[1]);

  /* 等待 Monitor 发送子进程 PID */
  if (read(sync_pipe[0], &cfg->rt.container_pid, sizeof(pid_t)) != sizeof(pid_t)) {
    log_error("Monitor 监控进程未能发送容器 PID。");
    if (lock_acquired)
      release_external_lock();
    goto cleanup;
  }
  close(sync_pipe[0]);
  sync_pipe[0] = -1;

  log_info("容器启动成功，主 PID 为 %d (Monitor PID: %d)", cfg->rt.container_pid,
           monitor_pid);

  if (cfg->conf.volatile_mode)
    log_info("正在进入易失模式 (OverlayFS)...");

  /* 9. 将挂载点状态同步到运行时配置 */
  if (cfg->conf.img_mount_point[0]) {
    cfg_t save_cfg = *cfg;
    config_save_by_name(cfg->conf.container_name, &save_cfg);
  }

  /* 10. 处理前台交互或后台脱离 */
  if (cfg->rt.foreground) {
    if (lock_acquired) {
      release_external_lock();
    }
    int ret = console_monitor_loop(cfg->rt.console.master, monitor_pid, cfg);
    return ret;
  } else {
    /* 后台模式：等待 pivot_root 完成再显示状态 (最多 5 秒) */
    snprintf(marker, sizeof(marker), "/proc/%d/root/run/" PROJECT_NAME,
             cfg->rt.container_pid);
    for (int i = 0; i < 50; i++) {
      if (access(marker, F_OK) == 0) {
        booted = true;
        break;
      }
      if (kill(cfg->rt.container_pid, 0) < 0 && errno == ESRCH)
        break;
      usleep(100000); 
    }

    if (!booted) {
      log_error("容器未能正确完成引导流程。");
      goto cleanup;
    }

    show_info(cfg, true);
    log_info("容器 '%s' 正在后台运行。", cfg->conf.container_name);
  }

  if (lock_acquired)
    release_external_lock();

  return 0;

cleanup:
  /* ==== 集中清理流程 ==== */
  if (has_side_effects) {
    cleanup_container_resources(cfg, true);
  }
  if (lock_acquired)
    release_external_lock();

  if (cfg->rt.console.master >= 0) {
    close(cfg->rt.console.master);
    cfg->rt.console.master = -1;
  }
  if (sync_pipe[0] >= 0)
    close(sync_pipe[0]);
  if (sync_pipe[1] >= 0)
    close(sync_pipe[1]);

  return -1;
}

static int stop_rootfs_with_timeout(cfg_t *cfg, int timeout_seconds) {
  if (timeout_seconds < 0)
    timeout_seconds = STOP_TIMEOUT;

  /* 获取外部命令锁 */
  if (acquire_external_lock(cfg->conf.container_name) != 0) {
    log_error("无法停止 '%s': 另一个命令正在管理此容器",
              cfg->conf.container_name);
    return -1;
  }

  pid_t pid = 0;
  if (!is_container_running(cfg->conf.uuid, &pid) || pid <= 0) {
    log_error("容器 '%s' 未运行或状态无效。", cfg->conf.container_name);
    release_external_lock();
    return -1;
  }

  log_info("正在停止容器 '%s' (PID %d)...", cfg->conf.container_name, pid);

  /* 安全的元数据捕获 */
  if (cfg->conf.img_mount_point[0] == '\0') {
    read_proc_environ(pid, "RUNTIME_MOUNT_PATH", cfg->conf.img_mount_point,
                      sizeof(cfg->conf.img_mount_point));
  }

  /* 1. 发送关闭信号 */
  kill(pid, SIGRTMIN + 3);

  log_info("正在等待容器优雅关闭 (最长可能需要 %d 秒)...", timeout_seconds);

  /* 2. 等待进程退出 */
  bool stopped = false;
  for (int i = 0; i < timeout_seconds * 5; i++) {
    if (kill(pid, 0) < 0) {
      if (errno == ESRCH) {
        stopped = true;
        break;
      }
    }
    usleep(RETRY_DELAY_US);
  }

  /* 3. 如果仍然存活，强制杀死 */
  bool unkillable = false;
  if (!stopped) {
    log_warn("优雅关闭超时，正在发送 SIGKILL 信号...");
    kill(pid, SIGKILL);

    bool killed = false;
    for (int j = 0; j < 25; j++) {
      if (kill(pid, 0) < 0 && errno == ESRCH) {
        killed = true;
        break;
      }
      usleep(RETRY_DELAY_US);
    }

    if (!killed) {
      unkillable = true;
      log_error("容器进程 (PID %d) 进入了不可杀死的僵尸状态！", pid);
      log_warn("这通常是因为内核僵尸进程导致。\n将尽最大努力清理宿主机资源 (无数据同步)...");
    }
  }

  /* 4. 清理固件路径 */
  if (cfg->conf.img_mount_point[0] && !unkillable && cfg->conf.hw_access) {
    char fw_path[PATH_MAX + 16];
    snprintf(fw_path, sizeof(fw_path), "%s/lib/firmware", cfg->conf.img_mount_point);
    firmware_path_remove(fw_path);
  }

  /* 5. 执行完整资源清理 */
  cleanup_container_resources(cfg, unkillable);

  if (!cfg->rt.foreground)
    log_info("容器 '%s' 已停止。", cfg->conf.container_name);

  release_external_lock();

  return 0;
}

int stop_rootfs(cfg_t *cfg) {
  return stop_rootfs_with_timeout(cfg, STOP_TIMEOUT);
}

/* 后续函数（show_info 等）因为没有用到 goto，且原样迁移即可 */
static const char *get_architecture(void) {
  static struct utsname uts;
  if (uname(&uts) != 0)
    return "unknown";
  return uts.machine;
}

static void parse_pretty_name(FILE *fp, char *buf, const size_t size) {
  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
      char *val = line + 12;
      size_t len = strlen(val);
      while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '"'))
        val[--len] = '\0';
      if (val[0] == '"') {
        val++;
        len--;
      }
      if (len >= size)
        len = size - 1;
      snprintf(buf, size, "%.*s", (int)len, val);
      return;
    }
  }
}

static void get_os_pretty(const char *osrelease_path, char *buf, const size_t size) {
  if (!buf || size == 0)
    return;
  buf[0] = '\0';

  auto_fclose FILE *fp = fopen(osrelease_path, "r");
  if (!fp)
    return;

  parse_pretty_name(fp, buf, size);
}

int show_info(cfg_t *cfg, const bool trust_cfg_pid) {
  if (cfg->conf.container_name[0] == '\0') {
    log_error("未指定容器名称。");
    return 0;
  }

  if (!trust_cfg_pid) {
    config_load_by_name(cfg->conf.container_name, cfg);
  }

  pid_t pid = 0;
  if (trust_cfg_pid) {
    pid = cfg->rt.container_pid;
  } else {
    is_container_running(cfg->conf.uuid, &pid);
  }

  if (pid <= 0) {
    log_error("容器 '%s' 未运行或状态无效。", cfg->conf.container_name);
    return -1;
  }

  const char *arch = get_architecture();
  printf("宿主机架构: %s\n", arch);

  printf("\n容器: %s (运行中)\n",
         cfg->conf.container_name);
  printf("  PID: %d\n", pid);

  char pretty[256];
  char osr_path[PATH_MAX];
  if (build_proc_root_path(pid, OS_RELEASE, osr_path,
                           sizeof(osr_path)) == 0) {
    get_os_pretty(osr_path, pretty, sizeof(pretty));
    if (pretty[0])
      printf("  操作系统: %s\n", pretty);
  }

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

  if (cfg->conf.hw_access) {
    printf("  硬件直通: 完整\n");
    feat_count++;
  } else if (cfg->conf.gpu_mode) {
    printf("  硬件直通: 仅 GPU\n");
    feat_count++;
  }

  if (cfg->conf.volatile_mode) {
    printf("  易失模式: 是\n");
    feat_count++;
  }

  if (cfg->conf.force_cgroupv1) {
    printf("  强制 Cgroup V1: 是\n");
    feat_count++;
  }

  if (cfg->conf.block_nested_ns) {
    printf("  死锁保护护盾: 是\n");
    feat_count++;
  }

  if (cfg->conf.privileged_mask > 0) {
    printf("  特权模式掩码: ");
    if (cfg->conf.privileged_mask == PRIV_FULL) {
      printf("完整(full)");
    } else {
      bool first = true;
      if (cfg->conf.privileged_mask & PRIV_NOMASK) {
        printf("%snomask", first ? "" : ", ");
        first = false;
      }
      if (cfg->conf.privileged_mask & PRIV_NOCAPS) {
        printf("%snocaps", first ? "" : ", ");
        first = false;
      }
      if (cfg->conf.privileged_mask & PRIV_NOSEC) {
        printf("%snoseccomp", first ? "" : ", ");
        first = false;
      }
      if (cfg->conf.privileged_mask & PRIV_SHARED) {
        printf("%sshared", first ? "" : ", ");
        first = false;
      }
      if (cfg->conf.privileged_mask & PRIV_UNFILT) {
        printf("%sunfiltered-dev", first ? "" : ", ");
        first = false;
      }
    }
    printf("\n");
    feat_count++;
  }

  if (feat_count == 0) {
    printf("  (无)\n");
  }

  if (!trust_cfg_pid &&
      (cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit) &&
      !cfg->conf.force_cgroupv1 && cgroup_host_is_v2()) {
    long long mu = -1, cu = -1, pu = -1;
    cgroup_get_usage(cfg->conf.container_name, &mu, &cu, &pu);
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