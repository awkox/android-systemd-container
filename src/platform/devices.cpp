#include "asc.h"

struct DeviceConfig {
    std::string_view name;
    mode_t mode;
    dev_t dev;
};

static int create_devices() {
  static const std::array devices{
    DeviceConfig{"null",    S_IFCHR | 0666, makedev(1, 3)},
    DeviceConfig{"zero",    S_IFCHR | 0666, makedev(1, 5)},
    DeviceConfig{"full",    S_IFCHR | 0666, makedev(1, 7)},
    DeviceConfig{"random",  S_IFCHR | 0666, makedev(1, 8)},
    DeviceConfig{"urandom", S_IFCHR | 0666, makedev(1, 9)},
    DeviceConfig{"tty",     S_IFCHR | 0666, makedev(5, 0)},
    DeviceConfig{"console", S_IFCHR | 0620, makedev(5, 1)},
    DeviceConfig{"ptmx",    S_IFCHR | 0666, makedev(5, 2)},
  };

  for (const auto& [name, mode, dev] : devices) {
    fs::path device_path = fs::path("dev") / name;

    std::error_code ec;
    fs::remove(device_path, ec); 

    if (mknod(device_path.c_str(), mode, dev) < 0) {
      log_error("创建设备节点 %s 失败: %s", device_path.c_str(), strerror(errno));
      return -1;
    } 
    
    chmod(device_path.c_str(), mode & 0777);
    if (name == "console" || name == "tty") {
      if (chown(device_path.c_str(), 0, 5) < 0) {
        // 可以记录日志，或者显式忽略警告
      }
    }
  }

  mkdir("dev/net", 0755);

  fs::remove("dev/net/tun");
  if (mknod("dev/net/tun", S_IFCHR | 0666, makedev(10, 200)) < 0) {
    log_warn("无法创建网络隧道节点 /dev/net/tun: %s", strerror(errno));
  } else {
    chmod("dev/net/tun", 0666);
  }

  fs::remove("dev/fuse");
  if (mknod("dev/fuse", S_IFCHR | 0666, makedev(10, 229)) < 0) {
    log_warn("无法创建 FUSE 节点 /dev/fuse: %s", strerror(errno));
  } else {
    chmod("dev/fuse", 0666);
  }

  /* 
   * [移除] 遵循 systemd CONTAINER_INTERFACE.md 规范:
   * 已移除对 /dev/fd, /dev/stdin, /dev/stdout, /dev/stderr 的手动符号链接创建。
   * 因为作为专业的 systemd 容器引擎，应当交由 systemd 的 systemd-tmpfiles 
   * 或 mount_setup 阶段自行接管这些标准输入输出流的链接。
   */

  return 0;
}

int setup_dev() {
  mkdir("dev", 0755);

  if (domount("none", "dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "size=8M,mode=755") < 0)
    return -1;

  return create_devices();
}

int setup_devpts() {
  const fs::path pts_path = "/dev/pts";
  const fs::path pts_ptmx = "/dev/pts/ptmx";
  const fs::path ptmx_path = "/dev/ptmx";
  
  create_directories_with_permission(pts_path);

  std::string gid_opt = "gid=" + std::to_string(DEFAULT_TTY_GID);
  std::array<std::string, 5> mount_opts = {
    gid_opt + ",newinstance,ptmxmode=0666,mode=0620",
    "newinstance,ptmxmode=0666,mode=0620",
    gid_opt + ",newinstance,mode=0620",
    "newinstance,ptmxmode=0666",
    "newinstance"
  };

  bool mount_success = false;
  for (const auto& opt : mount_opts) {
    if (domount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, opt.c_str()) == 0) {
      mount_success = true;
      break;
    }
  }

  if (!mount_success) {
    log_error("挂载 devpts (newinstance) 失败");
    return -1;
  }

  auto setup_ptmx_fallback = [&]() -> bool {
    std::error_code ec;
    // 策略 1: Bind Mount
    fs::remove(ptmx_path, ec);
    if (write_file(ptmx_path, "") == 0) {
      if (mount(pts_ptmx.c_str(), ptmx_path.c_str(), nullptr, MS_BIND, nullptr) == 0) {
        return true;
      }
    }

    // 策略 2: Symlink
    fs::remove(ptmx_path, ec);
    if (symlink("pts/ptmx", ptmx_path.c_str()) == 0 && fs::exists(pts_ptmx, ec)) {
      return true;
    }

    // 策略 3: mknod 兜底
    fs::remove(ptmx_path, ec);
    if (mknod(ptmx_path.c_str(), S_IFCHR | 0666, makedev(5, 2)) == 0) {
      chmod(ptmx_path.c_str(), 0666);
      return true;
    }

    return false;
  };

  if (!setup_ptmx_fallback()) {
    log_warn("无法虚拟化 /dev/ptmx，部分伪终端应用可能会失败");
  }

  return 0;
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