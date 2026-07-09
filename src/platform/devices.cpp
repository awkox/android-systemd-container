#include "asc.h"

static int create_devices(const char *rootfs) {
  const struct {
    const char *name;
    mode_t mode;
    dev_t dev;
  } devices[] = {
    {"null", S_IFCHR | 0666, makedev(1, 3)},
    {"zero", S_IFCHR | 0666, makedev(1, 5)},
    {"full", S_IFCHR | 0666, makedev(1, 7)},
    {"random", S_IFCHR | 0666, makedev(1, 8)},
    {"urandom", S_IFCHR | 0666, makedev(1, 9)},
    {"tty", S_IFCHR | 0666, makedev(5, 0)},
    {"console", S_IFCHR | 0620, makedev(5, 1)},
    {"ptmx", S_IFCHR | 0666, makedev(5, 2)},
    {nullptr, 0, 0}
  };

  char path[PATH_MAX];

  for (int i = 0; devices[i].name; i++) {
    snprintf(path, sizeof(path), "%s/dev/%s", rootfs, devices[i].name);

    fs::remove(path);

    if (mknod(path, devices[i].mode, devices[i].dev) < 0) {
      fs::path host_path = fs::path("/dev") / devices[i].name;
      bind_mount(host_path.c_str(), path);
    } else {
      chmod(path, devices[i].mode & 0777);
      if (strcmp(devices[i].name, "console") == 0 ||
          strcmp(devices[i].name, "tty") == 0) {
        if (chown(path, 0, 5) < 0) {}
      }
    }
  }

  snprintf(path, sizeof(path), "%s/dev/net", rootfs);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/dev/net/tun", rootfs);
  fs::remove(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 200)) < 0)
    bind_mount("/dev/net/tun", path);
  else
    chmod(path, 0666);

  snprintf(path, sizeof(path), "%s/dev/fuse", rootfs);
  fs::remove(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 229)) < 0)
    bind_mount("/dev/fuse", path);
  else
    chmod(path, 0666);

  char tgt[PATH_MAX];
  snprintf(tgt, sizeof(tgt), "%s/dev/fd", rootfs);
  if (symlink("/proc/self/fd", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/fd 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdin", rootfs);
  if (symlink("/proc/self/fd/0", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stdin 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdout", rootfs);
  if (symlink("/proc/self/fd/1", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stdout 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stderr", rootfs);
  if (symlink("/proc/self/fd/2", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stderr 符号链接失败: %s", strerror(errno));

  return 0;
}

int setup_dev(const char *rootfs) {
  char dev_path[PATH_MAX];
  snprintf(dev_path, sizeof(dev_path), "%s/dev", rootfs);

  mkdir(dev_path, 0755);

  if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
              "size=8M,mode=755") < 0)
    return -1;

  return create_devices(rootfs);
}

int setup_devpts() {
  const char *pts_path = "/dev/pts";

  umount2(pts_path, MNT_DETACH);
  mkdir(pts_path, 0755);

  char optbuf[256];
  snprintf(optbuf, sizeof(optbuf), "gid=%d,newinstance,ptmxmode=0666,mode=0620",
           DEFAULT_TTY_GID);

  char optbuf2[128];
  snprintf(optbuf2, sizeof(optbuf2), "gid=%d,newinstance,mode=0620",
           DEFAULT_TTY_GID);

  const char *opts[] = {
    optbuf,
    "newinstance,ptmxmode=0666,mode=0620",
    optbuf2,
    "newinstance,ptmxmode=0666",
    "newinstance",
    nullptr
  };

  for (int i = 0; opts[i]; i++) {
    if (domount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, opts[i]) == 0) {
      const char *ptmx_path = "/dev/ptmx";
      const char *pts_ptmx = "/dev/pts/ptmx";

      fs::remove(ptmx_path);

      if (write_file(ptmx_path, "") == 0) {
        if (mount(pts_ptmx, ptmx_path, nullptr, MS_BIND, nullptr) == 0) {
          return 0;
        }
      }

      fs::remove(ptmx_path);
      if (symlink("pts/ptmx", ptmx_path) == 0 && fs::exists(pts_ptmx))
        return 0;

      fs::remove(ptmx_path);
      if (mknod(ptmx_path, S_IFCHR | 0666, makedev(5, 2)) == 0) {
        chmod(ptmx_path, 0666);
        return 0;
      }

      log_warn("无法虚拟化 /dev/ptmx，部分伪终端应用可能会失败");
      return 0;
    }
  }

  log_error("挂载 devpts (newinstance) 失败");
  return -1;
}

int fix_host_ptys(void) {
  const char *pts_path = "/dev/pts";

  if (is_mountpoint(pts_path))
    return 0;

  mkdir(pts_path, 0755);

  if (mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC,
            "gid=5,mode=620") < 0) {
    if (errno != EBUSY) {
      log_warn("恢复宿主机 devpts 失败: %s", strerror(errno));
      return -1;
    }
  }

  log_info("宿主机 devpts 已成功恢复挂载 (Recovery 环境修复)。");
  return 0;
}
