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
#include <string>
#include <format>

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
#include "utils/log.h"
#include "cleanup.h"

namespace fs = std::filesystem;

// 常量定义
constexpr int MIN_KERNEL_MAJOR = 4;
constexpr int MIN_KERNEL_MINOR = 9;
constexpr int UUID_LEN = 32;
constexpr int MAX_CONTAINERS = 1024;
constexpr int STOP_TIMEOUT = 15;
constexpr unsigned int RETRY_DELAY_US = 200000;
constexpr int REBOOT_EXIT = 249;
constexpr int NL_BUFSIZE = 8192;
constexpr int BIND_INITIAL_CAP = 4;
constexpr int DEFAULT_TTY_GID = 5;
constexpr int MAX_TRACKED_ENTRIES = 512;

// 运行时路径
#define RUNTIME_DIR "/tmp/asc"
#define RUNTIME_LOCK_SUBDIR "lock"
#define RUNTIME_CONFIG_SUBDIR "config"
#define RUNTIME_LOGS_SUBDIR "logs"
#define RUNTIME_VOLATILE_SUBDIR "volatile"
#define RUNTIME_MNT_SUBDIR "mnt"
#define IMG_MOUNT_ROOT "/mnt/asc"
#define DEFAULT_INIT "/sbin/init"
#define ANDROID_TMPFS_CONTEXT "u:object_r:tmpfs:s0"

// 通用路径与模式
#define PROC_ROOT_FMT "/proc/%d/root"
#define PROC_CMDLINE_FMT "/proc/%d/cmdline"
#define PROC_STATUS_FMT "/proc/%d/status"
#define PROC_MOUNTINFO "/proc/self/mountinfo"
#define OS_RELEASE "/etc/os-release"
#define FW_PATH_FILE "/sys/module/firmware_class/parameters/path"
#define FORK_MARKER "/run/asc"
#define VPROC_PATH "/run/asc/vproc"

// 特权掩码定义
constexpr int PRIV_NOMASK = 1 << 0;
constexpr int PRIV_NOCAPS = 1 << 1;
constexpr int PRIV_NOSEC  = 1 << 2;
constexpr int PRIV_SHARED = 1 << 3;
constexpr int PRIV_UNFILT = 1 << 4;
constexpr int PRIV_FULL   = 0xFF;

typedef struct {
  int fd;
  uint32_t seq;
  pid_t pid;
} nl_ctx_t;

struct tty_info {
  int master;
  int slave;
  char name[PATH_MAX];
};

struct container_info {
  char name[128];
  pid_t pid;
};

typedef struct {
  char rootfs_img_path[PATH_MAX];
  char container_name[256];
  char uuid[UUID_LEN + 1];
  char img_mount_point[PATH_MAX];
  char custom_init[PATH_MAX];

  bool hw_access;
  bool gpu_mode;
  bool volatile_mode;
  bool force_cgroupv1;
  bool isolation_network;
  bool block_nested_ns;
  int privileged_mask;

  long long memory_limit;
  long long pids_limit;
  long long cpu_quota;
  long long cpu_period;
} asc_conf_t;

typedef struct {
  bool foreground;
  bool reboot_cycle;
  bool config_file_existed;

  char volatile_dir[PATH_MAX];
  char config_file[PATH_MAX];

  pid_t container_pid;

  struct tty_info console;
  struct timespec start_time;
  unsigned long ns_inode;
} asc_rt_t;

typedef struct {
  asc_conf_t conf;
  asc_rt_t rt;
} cfg_t;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#endif
