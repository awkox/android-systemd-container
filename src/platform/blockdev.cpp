#include "asc.h"

const char *detect_fs_type(const fs::path& img_path) {
  auto_close const int fd = open(img_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return nullptr;

  uint8_t buf[8];
  const char *result = nullptr;

  if (pread(fd, buf, 2, 0x438) == 2) {
    const uint16_t m = (uint16_t)buf[0] | (uint16_t)buf[1] << 8;
    if (m == 0xEF53) {
      result = "ext4";
      goto out;
    }
  }

  if (pread(fd, buf, 8, 0x10040) == 8) {
    if (memcmp(buf, "_BHRfS_M", 8) == 0) {
      result = "btrfs";
    }
  }

out:
  return result;
}

/*
 * 终极优化版 open_loop_dev: 
 * 1. 0 毫秒延迟（不等待 ueventd）
 * 2. 100% 设备号精准（通过 sysfs 向内核查询，完美解决 Android 乘以 8 的次设备号偏移）
 */
static int open_loop_dev(const long devnr, char *path_out, const size_t path_size) {
  char sysfs_path[128];
  snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/block/loop%ld/dev", devnr);

  // 1. 同步读取内核分配的确切设备号
  auto_fclose FILE *f = fopen(sysfs_path, "re");
  if (!f) {
    log_error("无法读取 loop%ld 的 sysfs 状态", devnr);
    return -1;
  }

  int major = 0, minor = 0;
  if (fscanf(f, "%d:%d", &major, &minor) != 2) {
    log_error("无法解析 loop%ld 的设备号", devnr);
    return -1;
  }

  // 2. 在 /tmp 创建私有的临时节点，绝对避免与宿主机 udev 发生权限和竞态冲突
  snprintf(path_out, path_size, "/dev/asc_loop_%ld", devnr);
  unlink(path_out); // 清理可能的残留

  // 3. 使用内核告诉我们的确切设备号创建节点
  if (mknod(path_out, S_IFBLK | 0600, makedev(major, minor)) == 0) {
    return open(path_out, O_RDWR | O_CLOEXEC);
  }

  return -1;
}

int loop_attach(const fs::path& img_path, char *loop_path_out, const size_t path_size) {
  auto_close const int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl_fd < 0) {
    log_error("打开 /dev/loop-control 失败: %s", strerror(errno));
    return -1;
  }

  const long devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
  if (devnr < 0) {
    log_error("请求空闲的 loop 设备失败: %s", strerror(errno));
    return -1;
  }

  const int loop_fd = open_loop_dev(devnr, loop_path_out, path_size);
  if (loop_fd < 0) {
    log_error("创建/打开 loop 设备节点失败: %s", strerror(errno));
    return -1;
  }

  auto_close const int img_fd = open(img_path.c_str(), O_RDWR | O_CLOEXEC);
  if (img_fd < 0) {
    log_error("打开镜像文件 %s 失败: %s", img_path.c_str(), strerror(errno));
    close(loop_fd);
    return -1;
  }

  /* 使用 LOOP_CONFIGURE 完成原子的全套挂载配置 */
  struct loop_config config = {};
  config.fd = img_fd;
  config.info.lo_flags = LO_FLAGS_AUTOCLEAR; // 内核会在卸载后自动清理销毁
  snprintf((char *)config.info.lo_file_name, LO_NAME_SIZE, "%.63s", img_path.c_str());

  if (ioctl(loop_fd, LOOP_CONFIGURE, &config) < 0) {
    log_error("LOOP_CONFIGURE 绑定失败: %s", strerror(errno));
    close(loop_fd);
    return -1;
  }

  return loop_fd;
}