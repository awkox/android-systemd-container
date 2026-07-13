#include "asc.h"

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
