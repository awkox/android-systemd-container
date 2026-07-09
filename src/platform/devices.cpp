#include "asc.h"

struct DeviceConfig {
    std::string_view name;
    mode_t mode;
    dev_t dev;
};

struct SymlinkPair {
    const char* target;
    const char* link;
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
    DeviceConfig{"ptmx",    S_IFCHR | 0666, makedev(5, 2)}
  };
  
  constexpr std::array symlinks{
    SymlinkPair{"/proc/self/fd",   "dev/fd"},
    SymlinkPair{"/proc/self/fd/0", "dev/stdin"},
    SymlinkPair{"/proc/self/fd/1", "dev/stdout"},
    SymlinkPair{"/proc/self/fd/2", "dev/stderr"}
  };

  for (const auto& [name, mode, dev] : devices) {
    fs::path device_path = fs::path("dev") / name;

    std::error_code ec;
    fs::remove(device_path, ec); 

    if (mknod(device_path.c_str(), mode, dev) < 0) {
      fs::path host_path = "/" / device_path; 
      bind_mount(host_path.c_str(), device_path.c_str());
    } else {
      chmod(device_path.c_str(), mode & 0777);
      
      if (name == "console" || name == "tty") {
        if (chown(device_path.c_str(), 0, 5) < 0) {
          // 可以记录日志，或者显式忽略警告
        }
      }
    }
  }

  mkdir("dev/net", 0755);

  fs::remove("dev/net/tun");
  if (mknod("dev/net/tun", S_IFCHR | 0666, makedev(10, 200)) < 0)
    bind_mount("/dev/net/tun", "dev/net/tun");
  else
    chmod("dev/net/tun", 0666);

  fs::remove("dev/fuse");
  if (mknod("dev/fuse", S_IFCHR | 0666, makedev(10, 229)) < 0)
    bind_mount("/dev/fuse", "dev/fuse");
  else
    chmod("dev/fuse", 0666);

  for (const auto& [target, link] : symlinks) {
    std::error_code ec;
    
    fs::create_symlink(target, link, ec);
    
    if (ec && ec != std::errc::file_exists) {
      log_warn("建立 %s 符号链接失败: %s", link, ec.message().c_str());
    }
  }

  return 0;
}

int setup_dev() {
  mkdir("dev", 0755);

  if (domount("none", "dev", "tmpfs", MS_NOSUID | MS_NOEXEC,
              "size=8M,mode=755") < 0)
    return -1;

  return create_devices();
}

int setup_devpts() {
  const fs::path pts_path = "/dev/pts";
  const fs::path ptmx_path = "/dev/ptmx";
  const fs::path pts_ptmx = "/dev/pts/ptmx";

  umount2(pts_path.c_str(), MNT_DETACH);
  
  std::error_code ec;
  fs::create_directories(pts_path, ec);

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
    if (domount("devpts", pts_path.c_str(), "devpts", MS_NOSUID | MS_NOEXEC, opt.c_str()) == 0) {
      mount_success = true;
      break;
    }
  }

  if (!mount_success) {
    log_error("挂载 devpts (newinstance) 失败");
    return -1;
  }

  // 3. 提取 ptmx 虚拟化逻辑为 Lambda，展平深深的 if 嵌套
  auto setup_ptmx_fallback = [&]() -> bool {
    // 策略 1: Bind Mount
    fs::remove(ptmx_path, ec);
    if (write_file(ptmx_path.c_str(), "") == 0) {
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

  // 4. 执行并检查最终状态
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
