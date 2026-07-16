#include "asc.h"
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

struct DeviceConfig {
    std::string_view name;
    mode_t mode;
    dev_t dev;
};

int setup_dev() {
  static const std::array devices{
    DeviceConfig{"null",    S_IFCHR | 0666, makedev(1, 3)},
    DeviceConfig{"zero",    S_IFCHR | 0666, makedev(1, 5)},
    DeviceConfig{"full",    S_IFCHR | 0666, makedev(1, 7)},
    DeviceConfig{"random",  S_IFCHR | 0666, makedev(1, 8)},
    DeviceConfig{"urandom", S_IFCHR | 0666, makedev(1, 9)},
    DeviceConfig{"tty",     S_IFCHR | 0666, makedev(5, 0)},
    DeviceConfig{"ptmx",    S_IFCHR | 0666, makedev(5, 2)},
    DeviceConfig{"console", S_IFCHR | 0620, makedev(5, 1)},
  };

  for (const auto &[name, mode, dev] : devices) {
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

  return 0;
}

int setup_devpts() {
  static constexpr auto mount_opts = std::to_array<const char*>({
    "newinstance,ptmxmode=0666,mode=0620,gid=5",
    "newinstance,ptmxmode=0666,mode=0620",
    "newinstance"
  });

  bool mount_success = false;
  mkdir("dev/pts", 0777);
  for (const auto &opt : mount_opts) {
    if (mount("devpts", "dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, opt) == 0) {
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
    fs::remove("dev/ptmx", ec);
    if (write_file("dev/ptmx", "") == 0) {
      if (mount("dev/pts/ptmx", "dev/ptmx", nullptr, MS_BIND, nullptr) == 0) {
        return true;
      }
    }

    // 策略 2: Symlink
    fs::remove("dev/ptmx", ec);
    if (symlink("pts/ptmx", "dev/ptmx") == 0 && fs::exists("dev/pts/ptmx", ec)) {
      return true;
    }

    return false;
  };

  if (!setup_ptmx_fallback()) {
    log_warn("无法虚拟化 /dev/ptmx，部分伪终端应用可能会失败");
  }

  return 0;
}
