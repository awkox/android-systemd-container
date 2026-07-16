#ifndef ASC_COMMON_H
#define ASC_COMMON_H

#include <sys/types.h>
#include <ctime>
#include <string>
#include <filesystem>

// 常量定义
constexpr int PRIV_NOMASK = 1 << 0;
constexpr int PRIV_NOCAPS = 1 << 1;
constexpr int PRIV_NOSEC  = 1 << 2;
constexpr int PRIV_FULL   = 0xFF;

namespace asc {

struct tty_info {
  int master = -1;
  int slave  = -1;
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
  asc::conf conf;

  std::string container_name;

  bool foreground;
  bool reboot_cycle;

  pid_t container_pid;

  tty_info console;
  timespec start_time;
  unsigned long ns_inode;
};

}
#endif