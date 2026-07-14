#ifndef ASC_COMMON_H
#define ASC_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/xattr.h>

#include <linux/magic.h>
#include <linux/capability.h>
#include <linux/rtnetlink.h>
#include <linux/seccomp.h>
#include <linux/loop.h>
#include <linux/audit.h>
#include <linux/filter.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <ftw.h>
#include <wordexp.h>

#include "version.h"
#include "cleanup.h"

namespace fs = std::filesystem;

// 常量定义
constexpr int MIN_KERNEL_MAJOR = 4;
constexpr int MIN_KERNEL_MINOR = 9;
constexpr int STOP_TIMEOUT = 15;
constexpr unsigned int RETRY_DELAY_US = 200000;
constexpr int REBOOT_EXIT = 249;

// 运行时路径
#define DEFAULT_INIT "/sbin/init"
#define ANDROID_TMPFS_CONTEXT "u:object_r:tmpfs:s0"

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