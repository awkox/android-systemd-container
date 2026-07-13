#include "asc.h"

bool is_mountpoint(const fs::path& path) {
    struct stat st1, st2;
    if (::stat(path.c_str(), &st1) < 0) return false;
    if (::stat((path / "..").c_str(), &st2) < 0) return false;
    return st1.st_dev != st2.st_dev;
}

int domount(const std::string& src, const std::string& tgt, const char *fstype,
            const unsigned long flags, const char *data) {
  if (mount(src.c_str(), tgt.c_str(), fstype, flags, data) < 0) {
    if (errno != EBUSY) {
      log_error("挂载失败 %s 到 %s (%s): %s", src.empty() ? "none" : src.c_str(), 
                tgt.c_str(), fstype ? fstype : "none", strerror(errno));
      return -1;
    }
  }
  return 0;
}

int bind_mount(const fs::path& src, const fs::path& tgt) {
  auto_close const int src_fd = open(src.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
  if (src_fd < 0) return -1;

  struct stat st_src;
  if (fstat(src_fd, &st_src) < 0) return -1;
  if (S_ISLNK(st_src.st_mode)) { errno = ELOOP; return -1; }

  struct stat st_tgt;
  if (lstat(tgt.c_str(), &st_tgt) < 0) {
    if (path_has_symlink(tgt)) { errno = ELOOP; return -1; }
    if (S_ISDIR(st_src.st_mode)) {
      mkdir(tgt.c_str(), st_src.st_mode & 07777);
      if (chown(tgt.c_str(), st_src.st_uid, st_src.st_gid) < 0) {}
    } else { write_file(tgt, ""); }
  } else if (S_ISLNK(st_tgt.st_mode)) {
    errno = ELOOP; return -1;
  }

  fs::path fd_path = fs::path("/proc/self/fd") / std::to_string(src_fd);
  return domount(fd_path, tgt, nullptr, MS_BIND | MS_REC, nullptr);
}

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
  const char *mnt_data = (strcmp(fstype, "ext4") == 0) ? "nodelalloc,errors=remount-ro,init_itable=0" : nullptr;

  
  for (int attempt : std::views::iota(0, 3)) {
    if (attempt == 0)
      log_info("正在挂载 %s 格式的镜像 %s 到 %s...", fstype, img_path.c_str(), mount_point.c_str());
    else
      log_info("正在重试挂载 (第 %d/3 次尝试)...", attempt + 1);

    bool success = false;

    fs::path final_src = "";
    int loop_fd = loop_attach(img_path.c_str(), final_src);

    if (loop_fd >= 0) {
      const int ret = mount(final_src.c_str(), mount_point.c_str(), fstype, mnt_flags, mnt_data);
      if (ret == 0) {
        mount(nullptr, mount_point.c_str(), nullptr, MS_REMOUNT | mnt_flags, mnt_data);
        success = true;
      } else {
        log_warn("挂载 mount(%s, %s) 失败: %s", final_src.c_str(), fstype, strerror(errno));
      }
    }

    /* 优化重点：直接 close。依托内核 AUTOCLEAR，再也不用手动去管销毁 */
    if (loop_fd >= 0) {
      close(loop_fd);
    }

    if (success) return 0;

    if (attempt < 2) {
      sync();
      usleep(RETRY_DELAY_US * 5);
    }
  }
  return -1;
}

void unmount_rootfs_img(const fs::path& mount_point, const bool silent) {
  sync();
  umount2(mount_point.c_str(), MNT_DETACH);

  sync();
  usleep(RETRY_DELAY_US);
  if (is_mountpoint(mount_point)) {
    umount2(mount_point.c_str(), MNT_DETACH | MNT_FORCE);
    usleep(RETRY_DELAY_US / 2);
  }

  const bool still_mounted = is_mountpoint(mount_point);
  if (fs::remove(mount_point) || !still_mounted) {
    if (!silent)
      log_info("已成功卸载 rootfs 镜像 %s。", mount_point.c_str());
  } else if (errno != ENOENT) {
    if (!silent)
      log_warn("清理警告: 挂载点 %s 仍然处于繁忙或被占用状态。", mount_point.c_str());
  }
}