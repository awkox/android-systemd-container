#include "asc.h"

/* 探测超级块的魔数来识别文件系统类型 */
const char *detect_fs_type(const char *img_path) {
  auto_close const int fd = open(img_path, O_RDONLY | O_CLOEXEC);
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
 * 获取 LOOP_CTL_GET_FREE 后的 loop 设备节点路径。
 *
 * Android 用户态 (vold): /dev/block/loopN
 * Android Recovery + 桌面 Linux: /dev/loopN
 *
 * 策略: 探测环境偏好的路径，如果 ueventd/udev 有延迟则等待重试，
 * 交叉尝试另一个路径，作为最后手段自己用 mknod 创建 (主设备号 7, 次设备号=devnr)。
 */
static int open_loop_dev(const long devnr, char *path_out, const size_t path_size) {
  /* Android 优先尝试: /dev/block/loopN */
  snprintf(path_out, path_size, "/dev/block/loop%ld", devnr);

  /* 最多等待 500ms 让 ueventd/udev 创建设备节点 */
  for (int i = 0; i < 5; i++) {
    const int fd = open(path_out, O_RDWR | O_CLOEXEC);
    if (fd >= 0)
      return fd;
    usleep(100000);
  }

  /* 跨环境回退 (例如 Recovery 环境表现得像桌面 Linux) */
  snprintf(path_out, path_size, "/dev/loop%ld", devnr);

  int fd = open(path_out, O_RDWR | O_CLOEXEC);
  if (fd >= 0)
    return fd;

  /* 最后的手段：我们自己创建设备节点 */
  if (mknod(path_out, S_IFBLK | 0660, makedev(7, (int)devnr)) == 0) {
    fd = open(path_out, O_RDWR | O_CLOEXEC);
    if (fd >= 0)
      return fd;
  }

  return -1;
}

/*
 * 通过 ioctl 将 img_path 附加到空闲的 loop 设备上。
 * 设定 LO_FLAGS_AUTOCLEAR 标志，让内核在 umount 后自动释放该 loop 设备。
 * 成功时返回打开的 loop_fd（调用方在 mount 之后必须手动关闭）。
 * loop_path_out 里面会填充为了调用 mount() 而准备好的设备节点路径。
 */
int loop_attach(const char *img_path, char *loop_path_out,
                       const size_t path_size) {
  auto_close const int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl_fd < 0) {
    log_error("打开 /dev/loop-control 失败: %s", strerror(errno));
    return -1;
  }

  const long devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
  if (devnr < 0) {
    log_error("请求空闲的 loop 设备 (LOOP_CTL_GET_FREE) 失败: %s", strerror(errno));
    return -1;
  }

  const int loop_fd = open_loop_dev(devnr, loop_path_out, path_size);
  if (loop_fd < 0) {
    log_error("打开 loop 设备 loop%ld 失败: %s", devnr, strerror(errno));
    return -1;
  }

  auto_close const int img_fd = open(img_path, O_RDWR | O_CLOEXEC);
  if (img_fd < 0) {
    log_error("打开镜像文件 %s 失败: %s", img_path, strerror(errno));
    close(loop_fd);
    return -1;
  }

  if (ioctl(loop_fd, LOOP_SET_FD, img_fd) < 0) {
    log_error("分配镜像到 loop 失败 (LOOP_SET_FD): %s", strerror(errno));
    close(loop_fd);
    return -1;
  }

  /* AUTOCLEAR: 在 umount 且所有文件描述符关闭后，内核自动释放 loop 设备 */
  struct loop_info64 li = {};
  li.lo_flags = LO_FLAGS_AUTOCLEAR;
  snprintf((char *)li.lo_file_name, LO_NAME_SIZE, "%.63s", img_path);

  if (ioctl(loop_fd, LOOP_SET_STATUS64, &li) < 0)
    log_warn("配置 loop 状态失败 (LOOP_SET_STATUS64): %s (将继续执行)", strerror(errno));

  return loop_fd;
}

/* 显式通过 LOOP_CLR_FD 卸载 loop 设备（双重保险） */
void loop_detach(const char *loop_dev) {
  if (!loop_dev || !loop_dev[0])
    return;
  auto_close const int fd = open(loop_dev, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  ioctl(fd, LOOP_CLR_FD, 0);
}

/* 通过 /proc/mounts 找到给定的挂载点背后的块设备（loop 节点） */
int get_backing_dev(const char *mnt, char *dev_out, const size_t dev_size) {
  auto_fclose FILE *f = fopen("/proc/mounts", "r");
  if (!f)
    return -1;

  char line[PATH_MAX + 256];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    char dev[256], mntpt[PATH_MAX];
    if (sscanf(line, "%255s %4095s", dev, mntpt) == 2 &&
        strcmp(mntpt, mnt) == 0) {
      safe_strncpy(dev_out, dev, dev_size);
      found = true;
      break;
    }
  }
  return found ? 0 : -1;
}