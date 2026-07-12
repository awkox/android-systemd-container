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

/* ---------------------------------------------------------------------------
 * 通用挂载包装器
 * ---------------------------------------------------------------------------*/

int domount(const std::string& src, const std::string& tgt, const char *fstype,
            const unsigned long flags, const char *data) {
  if (mount(src.c_str(), tgt.c_str(), fstype, flags, data) < 0) {
    /* 忽略设备忙 (EBUSY) 错误（通常意味着已挂载） */
    if (errno != EBUSY) {
      log_error("挂载失败 %s 到 %s (%s): %s", src.empty() ? "none" : src.c_str(), tgt.c_str(),
                fstype ? fstype : "none", strerror(errno));
      return -1;
    }
  }
  return 0;
}

int bind_mount(const fs::path& src, const fs::path& tgt) {
  auto_close const int src_fd = open(src.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
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
  if (lstat(tgt.c_str(), &st_tgt) < 0) {
    /* 目标不存在 — 如果任何父组件是符号链接则拒绝
     * (lstat 只能防止最后一个组件被跟踪)。 */
    if (path_has_symlink(tgt.c_str())) {
      log_error("安全违规：绑定挂载的目标路径中包含符号链接 %s", tgt.c_str());
      errno = ELOOP;
      return -1;
    }
    if (S_ISDIR(st_src.st_mode)) {
      mkdir(tgt.c_str(), st_src.st_mode & 07777);
      if (chown(tgt.c_str(), st_src.st_uid, st_src.st_gid) < 0) {
        /* 忽略 chown 失败，这对绑定挂载并非致命 */
      }
    } else {
      write_file(tgt, "");
    }
  } else if (S_ISLNK(st_tgt.st_mode)) {
    log_error("安全违规：绑定挂载目标 %s 是一个符号链接！", tgt.c_str());
    errno = ELOOP;
    return -1;
  }

  fs::path fd_path = fs::path("/proc/self/fd") / std::to_string(src_fd);

  return domount(fd_path, tgt, nullptr, MS_BIND | MS_REC, nullptr);
}

/* ---------------------------------------------------------------------------
 * Rootfs 镜像处理 - 纯 C 实现的 loop 设备管理
 * ---------------------------------------------------------------------------*/

int mount_rootfs_img(const fs::path& img_path, const fs::path& mount_point) {
  if (!create_directories_with_permission(mount_point)) {
    log_error("创建挂载目录 %s 失败: %s", mount_point.c_str(), strerror(errno));
    return -1;
  }

  const char *fstype = detect_fs_type(img_path);
  if (!fstype) {
    log_warn("位于 %s 的文件系统未知。仅支持 ext4 和 btrfs。", img_path.c_str());
    return -1;
  }

  sync();
  usleep(RETRY_DELAY_US);

  constexpr unsigned long mnt_flags = MS_NOATIME | MS_NODIRATIME;
  const char *mnt_data = nullptr;

  if (strcmp(fstype, "ext4") == 0) {
    mnt_data = "nodelalloc,errors=remount-ro,init_itable=0";
  }

  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt == 0)
      log_info("正在挂载 %s 格式的镜像 %s 到 %s...", fstype, img_path.c_str(), mount_point.c_str());
    else
      log_info("正在重试挂载 (第 %d/3 次尝试)...", attempt + 1);

    struct stat st;
    const bool is_blk = stat(img_path.c_str(), &st) == 0 && S_ISBLK(st.st_mode);
    
    char final_src[PATH_MAX] = {0}; // 【新增初始化】
    int loop_fd = -1;
    bool success = false;

    if (is_blk) {
      safe_strncpy(final_src, img_path.c_str(), sizeof(final_src));
    } else {
      loop_fd = loop_attach(img_path.c_str(), final_src, sizeof(final_src));
    }

    if (is_blk || loop_fd >= 0) {
      const int ret = mount(final_src, mount_point.c_str(), fstype, mnt_flags, mnt_data);
      if (ret == 0) {
        mount(nullptr, mount_point.c_str(), nullptr, MS_REMOUNT | mnt_flags, mnt_data);
        success = true;
      } else {
        log_warn("挂载 mount(%s, %s) 失败: %s", final_src, fstype, strerror(errno));
      }
    }

    // 【修改点】：直接关闭 loop_fd。AUTOCLEAR 机制会接管内核资源的自动释放
    if (loop_fd >= 0) {
      close(loop_fd);
    }

    // 【修改点】：我们自己 mknod 的临时节点用完即删（无论成败，因为挂载已持有其内核对象引用）
    if (!is_blk && final_src[0] != '\0') {
      unlink(final_src);
    }

    if (success) {
      return 0;
    }

    if (attempt < 2) {
      log_info("将在 1 秒后重试...");
      sync();
      usleep(RETRY_DELAY_US * 5);
    }
  }

  log_error("重试 3 次后，依然无法挂载镜像 %s", img_path.c_str());
  return -1;
}

void unmount_rootfs_img(const fs::path& mount_point, const bool silent) {
  /* 1. 懒卸载 (Lazy unmount)：即使文件被打开也会立即从命名空间剥离 */
  sync();
  umount2(mount_point.c_str(), MNT_DETACH);

  /* 2. 沉淀一段时间，针对老旧内核强制执行 */
  sync();
  usleep(RETRY_DELAY_US);
  if (is_mountpoint(mount_point)) {
    umount2(mount_point.c_str(), MNT_DETACH | MNT_FORCE);
    usleep(RETRY_DELAY_US / 2);
  }

  /* 3. 目录清理和日志记录 */
  const bool still_mounted = is_mountpoint(mount_point);
  if (fs::remove(mount_point) || !still_mounted) {
    if (!silent)
      log_info("已成功卸载 rootfs 镜像 %s。", mount_point.c_str());
  } else if (errno != ENOENT) {
    if (!silent)
      log_warn("清理警告: 挂载点 %s 仍然处于繁忙或被占用状态。", mount_point.c_str());
  }
}