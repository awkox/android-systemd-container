#include "asc.h"

/* ---------------------------------------------------------------------------
 * 辅助函数
 * ---------------------------------------------------------------------------*/

bool is_mountpoint(const fs::path& path) {
    struct stat st1, st2;
    if (::stat(path.c_str(), &st1) < 0)
        return false;

    fs::path parent = path / "..";
    if (::stat(parent.c_str(), &st2) < 0)
        return false;

    return st1.st_dev != st2.st_dev;
}

/* 使用容器名称在 /mnt/asc/ 中查找或创建可用的挂载点 */
static int find_available_mountpoint(const char *name, char *mount_path,
                                     const size_t size) {
  const char *base_dir = IMG_MOUNT_ROOT;

  mkdir(base_dir, 0755);

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  snprintf(mount_path, size, "%s/%s", base_dir, safe_name);

  if (mkdir(mount_path, 0755) < 0) {
    log_error("创建挂载目录 %s 失败: %s", mount_path,
              strerror(errno));
    return -1;
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * 通用挂载包装器
 * ---------------------------------------------------------------------------*/

int domount(const char *src, const char *tgt, const char *fstype,
            const unsigned long flags, const char *data) {
  if (mount(src, tgt, fstype, flags, data) < 0) {
    /* 忽略设备忙 (EBUSY) 错误（通常意味着已挂载） */
    if (errno != EBUSY) {
      log_error("挂载失败 %s 到 %s (%s): %s", src ? src : "none", tgt,
                fstype ? fstype : "none", strerror(errno));
      return -1;
    }
  }
  return 0;
}

int bind_mount(const char *src, const char *tgt) {
  auto_close const int src_fd = open(src, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  if (src_fd < 0) {
    /* 遇到 ELOOP 说明它是一个我们应拒绝的符号链接 */
    return -1;
  }

  struct stat st_src;
  if (fstat(src_fd, &st_src) < 0)
    return -1;

  /* 显式拒绝符号链接 */
  if (S_ISLNK(st_src.st_mode)) {
    errno = ELOOP;
    return -1;
  }

  struct stat st_tgt;
  if (lstat(tgt, &st_tgt) < 0) {
    /* 目标不存在 — 如果任何父组件是符号链接则拒绝
     * (lstat 只能防止最后一个组件被跟踪)。 */
    if (path_has_symlink(tgt)) {
      log_error("安全违规：绑定挂载的目标路径中包含符号链接 %s", tgt);
      errno = ELOOP;
      return -1;
    }
    if (S_ISDIR(st_src.st_mode)) {
      mkdir(tgt, st_src.st_mode & 07777);
      if (chown(tgt, st_src.st_uid, st_src.st_gid) < 0) {
        /* 忽略 chown 失败，这对绑定挂载并非致命 */
      }
    } else {
      write_file(tgt, "");
    }
  } else if (S_ISLNK(st_tgt.st_mode)) {
    log_error("安全违规：绑定挂载目标 %s 是一个符号链接！", tgt);
    errno = ELOOP;
    return -1;
  }

  char proc_path[64];
  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", src_fd);

  return domount(proc_path, tgt, nullptr, MS_BIND | MS_REC, nullptr);
}

/* ---------------------------------------------------------------------------
 * /dev 与 OverlayFS 挂载设置
 * ---------------------------------------------------------------------------*/

int check_volatile_mode(asc_conf_t *conf) {
  if (!conf->volatile_mode)
    return 0;

  if (!grep_file("/proc/filesystems", "overlay")) {
    log_error("您的内核不支持 OverlayFS。无法使用易失模式。");
    return -1;
  }

  /* 预检：拒绝 f2fs 底层目录 - 这是已知的 Android 内核限制 */
  struct statfs sfs;
  if (statfs(conf->img_mount_point, &sfs) == 0 && sfs.f_type == 0xF2F52010) {
    log_error("无法使用易失模式：您的 rootfs 位于 f2fs 分区上，"
              "大多数 Android 内核不支持将其用作 OverlayFS 的下层。");
    log_error("提示：请在 f2fs 分区上使用镜像文件 (-i) 而不是目录 (-r) 来开启易失模式。");
    return -1;
  }

  return 0;
}

int setup_volatile_overlay(cfg_t *cfg) {
    // 使用 std::format 动态拼接字符串，绝对不会发生缓冲区溢出
    fs::path base = std::format("{}/{}/{}", 
                                get_runtime_dir(), 
                                RUNTIME_VOLATILE_SUBDIR, 
                                cfg->rt.container_name);

    if (mkdir_p(base, 0755) < 0) {
        log_error("创建易失模式工作区失败: %s", base.c_str());
        return -1;
    }
    safe_strncpy(cfg->rt.volatile_dir, base.c_str(), sizeof(cfg->rt.volatile_dir));

    if (domount("none", base.c_str(), "tmpfs", 0, "size=50%,mode=755") < 0)
        return -1;

    // 构建层级目录：优雅且跨平台
    fs::path upper  = base / "upper";
    fs::path work   = base / "work";
    fs::path merged = base / "merged";

    std::error_code ec;
    fs::create_directory(upper, ec);
    fs::create_directory(work, ec);
    fs::create_directory(merged, ec);

    // C++ 格式化挂载参数，彻底告别超大 char[] 缓冲和截断检查
    std::string opts = std::format("lowerdir={},upperdir={},workdir={},context=\"{}\"",
                                   cfg->conf.img_mount_point, 
                                   upper.string(), 
                                   work.string(), 
                                   ANDROID_TMPFS_CONTEXT);

    if (domount("overlay", merged.c_str(), "overlay", 0, opts.c_str()) < 0) {
        log_error("OverlayFS 挂载失败。");
        umount2(base.c_str(), MNT_DETACH);
        cleanup_volatile_overlay(&cfg->rt);
        return -1;
    }

    safe_strncpy(cfg->conf.img_mount_point, merged.c_str(), sizeof(cfg->conf.img_mount_point));
    return 0;
}

static bool is_mount_in_namespace(const char *path) {
  auto_fclose FILE *f = fopen("/proc/self/mountinfo", "r");
  if (!f)
    return false;

  char io_buf[65536];
  setvbuf(f, io_buf, _IOFBF, sizeof(io_buf));

  char line[4096];
  const size_t path_len = strlen(path);

  while (fgets(line, sizeof(line), f)) {
    const char *p = line;
    for (int skip = 0; skip < 4 && *p; skip++) {
      while (*p && *p != ' ')
        p++;
      while (*p == ' ')
        p++;
    }
    if (strncmp(p, path, path_len) == 0 &&
        (p[path_len] == ' ' || p[path_len] == '\n' || p[path_len] == '\0')) {
      return true;
    }
  }
  return false;
}

int cleanup_volatile_overlay(asc_rt_t *rt) {
  if (rt->volatile_dir[0] == '\0')
    return 0;

  char merged[PATH_MAX + 32];
  snprintf(merged, sizeof(merged), "%s/merged", rt->volatile_dir);

  if (!is_mount_in_namespace(merged) &&
      !is_mount_in_namespace(rt->volatile_dir)) {
    goto done;
  }

  sync();
  umount(merged);
  umount(rt->volatile_dir);

done:
  usleep(RETRY_DELAY_US / 2);
  const int r = remove_recursive(rt->volatile_dir);
  rt->volatile_dir[0] = '\0';
  return r;
}

/* ---------------------------------------------------------------------------
 * Rootfs 镜像处理 - 纯 C 实现的 loop 设备管理
 * ---------------------------------------------------------------------------*/

int mount_rootfs_img(const char *img_path, char *mount_point, const size_t mp_size,
                     const char *name) {
  if (find_available_mountpoint(name, mount_point, mp_size) < 0) {
    log_error("无法为 %s 找到可用的挂载点", name);
    return -1;
  }

  /* 探测镜像的超级块魔数以识别文件系统类型 */
  const char *fstype = detect_fs_type(img_path);
  if (!fstype) {
    log_warn("位于 %s 的文件系统未知。仅支持 ext4 和 btrfs。",
             img_path);
    return -1;
  }

  sync();
  usleep(RETRY_DELAY_US);

  constexpr unsigned long mnt_flags = MS_NOATIME | MS_NODIRATIME;
  const char *mnt_data = nullptr;

  if (strcmp(fstype, "ext4") == 0) {
    mnt_data = "nodelalloc,errors=remount-ro,init_itable=0";
  } else if (strcmp(fstype, "btrfs") == 0) {
    mnt_data = nullptr;
  }

  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt == 0)
      log_info("正在挂载 %s 格式的镜像 %s 到 %s...", fstype, img_path,
               mount_point);
    else
      log_info("正在挂载 %s 格式的镜像 %s 到 %s (第 %d/3 次尝试)...", fstype,
               img_path, mount_point, attempt + 1);

    struct stat st;
    const bool is_blk = stat(img_path, &st) == 0 && S_ISBLK(st.st_mode);
    char final_src[PATH_MAX];
    int loop_fd = -1;
    bool success = false;

    if (is_blk) {
      safe_strncpy(final_src, img_path, sizeof(final_src));
    } else {
      loop_fd = loop_attach(img_path, final_src, sizeof(final_src));
    }

    if (is_blk || loop_fd >= 0) {
      const int ret = mount(final_src, mount_point, fstype, mnt_flags, mnt_data);
      if (ret == 0) {
        /* Android 修复：针对部分内核的强制 nosuid 补丁进行读写重挂载 */
        mount(nullptr, mount_point, nullptr, MS_REMOUNT | mnt_flags, mnt_data);
        success = true;
      } else {
        log_warn("挂载 mount(%s, %s) 失败: %s", final_src, fstype, strerror(errno));
      }
    }

    /* 无论成败，如果打开了 loop_fd 均需要关闭 */
    if (loop_fd >= 0) {
      close(loop_fd);
      /* 如果挂载失败，手工分离；挂载成功内核的 AUTOCLEAR 会负责 */
      if (!success) {
        loop_detach(final_src);
      }
    }

    if (success) {
      return 0;
    }

    /* 准备下一次重试 */
    if (attempt < 2) {
      log_info("将在 1 秒后重试...");
      sync();
      usleep(RETRY_DELAY_US * 5);
    }
  }

  log_error("重试 3 次后，依然无法挂载镜像 %s", img_path);
  return -1;
}

void unmount_rootfs_img(const char *mount_point, const bool silent) {
  if (!mount_point || !mount_point[0])
    return;

  /* 1. 懒卸载 (Lazy unmount)：即使文件被打开也会立即从命名空间剥离 */
  sync();
  umount2(mount_point, MNT_DETACH);

  /* 2. 沉淀一段时间，针对老旧内核强制执行 */
  sync();
  usleep(RETRY_DELAY_US);
  if (is_mountpoint(mount_point)) {
    umount2(mount_point, MNT_DETACH | MNT_FORCE);
    usleep(RETRY_DELAY_US / 2);
  }

  /* 3. 目录清理和日志记录 */
  const bool still_mounted = is_mountpoint(mount_point);
  if (rmdir(mount_point) == 0 || !still_mounted) {
    if (!silent)
      log_info("已成功卸载 rootfs 镜像 %s。", mount_point);
  } else if (errno != ENOENT) {
    if (!silent)
      log_warn("清理警告: 挂载点 %s 仍然处于繁忙或被占用状态。", mount_point);
  }
}