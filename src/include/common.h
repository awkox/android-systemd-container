#ifndef ASC_COMMON_H
#define ASC_COMMON_H

#include <filesystem>
#include <string>
#include <sys/types.h>

// 常量定义
constexpr int PRIV_NOMASK = 1 << 0;
constexpr int PRIV_NOCAPS = 1 << 1;
constexpr int PRIV_NOSEC = 1 << 2;
constexpr int PRIV_FULL = 0xFF;

namespace asc {

struct tty_info {
  int master = -1;
  int slave = -1;
  std::filesystem::path name;
};

struct conf {
  std::filesystem::path rootfs_img_path;
  std::filesystem::path custom_init;

  bool isolation_network;
  bool block_nested_ns;
  int privileged_mask;
};

struct rt {
  conf cfg;

  std::string container_name;
  pid_t container_pid;

  bool foreground;
  bool reboot_cycle;

  tty_info console;
  unsigned long ns_inode;
};

} // namespace asc
#endif