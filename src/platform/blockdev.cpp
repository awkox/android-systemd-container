#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <format>
#include <algorithm>
#include <ranges>
#include <filesystem>
#include <string>
#include <linux/loop.h>
#include "platform/blockdev.h"
#include "utils/log.h"

/*
 * 终极优化版 open_loop_dev: 
 * 1. 0 毫秒延迟（不等待 ueventd）
 * 2. 100% 设备号精准（通过 sysfs 向内核查询，完美解决 Android 乘以 8 的次设备号偏移）
 */
static int open_loop_dev(const long devnr, std::filesystem::path &path_out) {
  const std::filesystem::path sysfs_path = std::format("/sys/class/block/loop{}/dev", devnr);
  // 1. 同步读取内核分配的确切设备号
  std::ifstream f(sysfs_path);
  if (!f) {
    log_error("无法读取 loop{} 的 sysfs 状态", devnr);
    return -1;
  }

  int major = 0, minor = 0;
  char colon;
  if (f >> major >> colon >> minor && colon == ':') {
    // 2. 在 /dev 创建私有的临时节点，绝对避免与宿主机 udev 发生权限和竞态冲突
    path_out.assign(std::format("/dev/asc_loop_{}", devnr));
    unlink(path_out.c_str()); // 清理可能的残留

    // 3. 使用内核告诉我们的确切设备号创建节点
    if (mknod(path_out.c_str(), S_IFBLK | 0600, makedev(major, minor)) < 0) {
      log_error("无法创建设备节点 {} (major={}, minor={})", path_out.c_str(), major, minor);
      return -1;
    }
    return open(path_out.c_str(), O_RDWR | O_CLOEXEC);
  }

  log_error("无法解析 loop{} 的设备号", devnr);
  return -1;
}

int loop_attach(const std::filesystem::path &img_path, std::filesystem::path &loop_path_out) {
  const int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl_fd < 0) {
    log_error("打开 /dev/loop-control 失败: {}", strerror(errno));
    return -1;
  }

  const long devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
  close(ctl_fd);
  if (devnr < 0) {
    log_error("请求空闲的 loop 设备失败: {}", strerror(errno));
    return -1;
  }

  const int loop_fd = open_loop_dev(devnr, loop_path_out);
  if (loop_fd < 0) {
    log_error("创建/打开 loop 设备节点失败: {}", strerror(errno));
    return -1;
  }

  const int img_fd = open(img_path.c_str(), O_RDWR | O_CLOEXEC);
  if (img_fd < 0) {
    log_error("打开镜像文件 {} 失败: {}", img_path.c_str(), strerror(errno));
    close(loop_fd);
    return -1;
  }

  /* 使用 LOOP_CONFIGURE 完成原子的全套挂载配置 */
  loop_config config = {};
  config.fd = img_fd;
  config.info.lo_flags = LO_FLAGS_AUTOCLEAR; // 内核会在卸载后自动清理销毁
  std::ranges::copy(img_path.string() | std::views::take(LO_NAME_SIZE - 1), config.info.lo_file_name);

  if (ioctl(loop_fd, LOOP_CONFIGURE, &config) < 0) {
    close(img_fd);
    log_error("LOOP_CONFIGURE 绑定失败: {}", strerror(errno));
    close(loop_fd);
    return -1;
  }
  close(img_fd);

  return loop_fd;
}