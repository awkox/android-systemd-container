#ifndef ASC_COMMON_H
#define ASC_COMMON_H

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <format>
#include <algorithm>
#include <array>
#include <optional>
#include <vector>
#include <stdexcept>
#include <ranges>

#include "version.h"

namespace fs = std::filesystem;

// 常量定义
constexpr int MIN_KERNEL_MAJOR = 4;
constexpr int MIN_KERNEL_MINOR = 9;
constexpr int STOP_TIMEOUT = 15;
constexpr unsigned int RETRY_DELAY_US = 200000;
constexpr int REBOOT_EXIT = 249;

// 运行时路径
constexpr const char* DEFAULT_INIT = "/sbin/init";

// 特权掩码定义
constexpr int PRIV_NOMASK = 1 << 0;
constexpr int PRIV_NOCAPS = 1 << 1;
constexpr int PRIV_NOSEC  = 1 << 2;
constexpr int PRIV_FULL   = 0xFF;


struct tty_info {
  int master = -1;
  int slave  = -1;
  fs::path name;
};

struct asc_conf_t {
  fs::path rootfs_img_path;
  fs::path custom_init;

  bool isolation_network;
  bool block_nested_ns;
  int privileged_mask;
};

struct asc_rt_t {
  std::string container_name;

  bool foreground;
  bool reboot_cycle;

  pid_t container_pid;

  tty_info console;
  timespec start_time;
  unsigned long ns_inode;
};

struct cfg_t {
  asc_conf_t conf;
  asc_rt_t rt;
};

int asc_main(int argc, char **argv);

#endif