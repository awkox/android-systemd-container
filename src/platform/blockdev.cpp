#include "asc.h"

/* 探测超级块的魔数来识别文件系统类型 */
const char *detect_fs_type(const fs::path& img_path) {
  auto_close const int fd = open(img_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return nullptr;

  uint8_t buf[8];
  const char *result = nullptr;

  /* 偏移 0x438: ext2/3/4 (0xEF53 LE 小端) */
  if (pread(fd, buf, 2, 0x438) == 2) {
    const uint16_t m = (uint16_t)buf[0] | (uint16_t)buf[1] << 8;
    if (m == 0xEF53) {
      result = "ext4";
      goto out;
    }
  }

  /* 偏移 0x10040: btrfs ("_BHRfS_M") */
  if (pread(fd, buf, 8, 0x10040) == 8) {
    if (memcmp(buf, "_BHRfS_M", 8) == 0) {
      result = "btrfs";
    }
  }

out:
  return result;
}

/*
 * 在专属运行目录直接创建临时节点，彻底消除 udev/ueventd 的异步延迟和环境差异
 */
static int open_loop_dev(const long devnr, char *path_out, const size_t path_size) {
  snprintf(path_out, path_size, "/tmp/asc/loop_%ld", devnr);
  
  // 确保旧的冲突节点被清理
  unlink(path_out);

  // 内核中 loop 的主设备号始终为 7
  if (mknod(path_out, S_IFBLK | 0600, makedev(7, (int)devnr)) == 0) {
    return open(path_out, O_RDWR | O_CLOEXEC);
  }
  return -1;
}

/*
 * 使用 Linux 5.8+ 的原子 ioctl (LOOP_CONFIGURE) 完成绑定
 */
int loop_attach(const fs::path& img_path, char *loop_path_out, const size_t path_size) {
  auto_close const int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl_fd < 0) {
    log_error("打开 /dev/loop-control 失败: %s", strerror(errno));
    return -1;
  }

  const long devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
  if (devnr < 0) {
    log_error("请求空闲 loop 设备失败: %s", strerror(errno));
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

  struct loop_config config = {};
  config.fd = img_fd;
  config.info.lo_flags = LO_FLAGS_AUTOCLEAR; // umount 且 close 后内核自动清理
  snprintf((char *)config.info.lo_file_name, LO_NAME_SIZE, "%.63s", img_path.c_str());

  if (ioctl(loop_fd, LOOP_CONFIGURE, &config) < 0) {
    log_error("LOOP_CONFIGURE 失败: %s", strerror(errno));
    close(loop_fd);
    return -1;
  }

  return loop_fd;
}