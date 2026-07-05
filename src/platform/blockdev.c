#include "asc.h"

/* Probe superblock magic bytes to identify the filesystem type. */
const char *detect_fs_type(const char *img_path) {
  auto_close int fd = open(img_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return nullptr;

  uint8_t buf[8];
  const char *result = nullptr;

  /* offset 0x438: ext2/3/4 (0xEF53 LE) */
  if (pread(fd, buf, 2, 0x438) == 2) {
    uint16_t m = (uint16_t)buf[0] | (uint16_t)buf[1] << 8;
    if (m == 0xEF53) {
      result = "ext4";
      goto out;
    }
  }

  /* offset 0x10040: btrfs ("_BHRfS_M") */
  if (pread(fd, buf, 8, 0x10040) == 8) {
    if (memcmp(buf, "_BHRfS_M", 8) == 0) {
      result = "btrfs";
      goto out;
    }
  }

out:
  return result;
}

/*
 * Resolve loop device node path after LOOP_CTL_GET_FREE.
 *
 * Android userspace (vold): /dev/block/loopN
 * Android recovery + desktop Linux: /dev/loopN
 *
 * Strategy: probe the environment-preferred path with retries for ueventd/udev,
 * cross-try the other path, then mknod as a last resort (major 7, minor=devnr).
 */
int open_loop_dev(long devnr, char *path_out, size_t path_size) {
  /* Android: /dev/block/loopN; recovery/desktop: /dev/loopN */
  snprintf(path_out, path_size, "/dev/block/loop%ld", devnr);

  /* Wait up to 500ms for ueventd/udev to create the node */
  for (int i = 0; i < 5; i++) {
    int fd = open(path_out, O_RDWR | O_CLOEXEC);
    if (fd >= 0)
      return fd;
    usleep(100000);
  }

  /* Cross-environment fallback (recovery acts like desktop, etc.) */
  snprintf(path_out, path_size, "/dev/loop%ld", devnr);

  int fd = open(path_out, O_RDWR | O_CLOEXEC);
  if (fd >= 0)
    return fd;

  /* Last resort: create the node ourselves */
  if (mknod(path_out, S_IFBLK | 0660, makedev(7, (int)devnr)) == 0) {
    fd = open(path_out, O_RDWR | O_CLOEXEC);
    if (fd >= 0)
      return fd;
  }

  return -1;
}

/*
 * Attach img_path to a free loop device via ioctls.
 * Sets LO_FLAGS_AUTOCLEAR so the kernel auto-releases the loop after umount.
 * Returns the open loop_fd on success (caller must close after mount()).
 * loop_path_out is filled with the device node path for the mount() call.
 */
int loop_attach(const char *img_path, char *loop_path_out,
                       size_t path_size) {
  auto_close int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl_fd < 0) {
    log_error("open /dev/loop-control: %s", strerror(errno));
    return -1;
  }

  long devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
  if (devnr < 0) {
    log_error("LOOP_CTL_GET_FREE: %s", strerror(errno));
    return -1;
  }

  int loop_fd = open_loop_dev(devnr, loop_path_out, path_size);
  if (loop_fd < 0) {
    log_error("Failed to open loop%ld: %s", devnr, strerror(errno));
    return -1;
  }

  auto_close int img_fd = open(img_path, O_RDWR | O_CLOEXEC);
  if (img_fd < 0) {
    log_error("open image %s: %s", img_path, strerror(errno));
    close(loop_fd);
    return -1;
  }

  if (ioctl(loop_fd, LOOP_SET_FD, img_fd) < 0) {
    log_error("LOOP_SET_FD: %s", strerror(errno));
    close(loop_fd);
    return -1;
  }

  /* AUTOCLEAR: kernel auto-releases loop device after umount + all fds closed
   */
  struct loop_info64 li = {
    .lo_flags = LO_FLAGS_AUTOCLEAR,
  };
  snprintf((char *)li.lo_file_name, LO_NAME_SIZE, "%.63s", img_path);

  if (ioctl(loop_fd, LOOP_SET_STATUS64, &li) < 0)
    log_warn("LOOP_SET_STATUS64: %s (continuing)", strerror(errno));

  return loop_fd;
}

/* Detach a loop device explicitly via LOOP_CLR_FD (belt-and-suspenders). */
void loop_detach(const char *loop_dev) {
  if (!loop_dev || !loop_dev[0])
    return;
  auto_close int fd = open(loop_dev, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  ioctl(fd, LOOP_CLR_FD, 0);
}

/* Find the block device (loop node) backing a given mount point via
 * /proc/mounts. */
int get_backing_dev(const char *mnt, char *dev_out, size_t dev_size) {
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
