#ifndef ASC_H
#define ASC_H

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

#include "version.h"
#include "utils/log.h"
#include "cleanup.h"

// 常量定义
constexpr int MIN_KERNEL_MAJOR = 4;
constexpr int MIN_KERNEL_MINOR = 9;
constexpr int UUID_LEN = 32;
constexpr int MAX_CONTAINERS = 1024;
constexpr int STOP_TIMEOUT = 15; /* 秒 */
constexpr unsigned int RETRY_DELAY_US = 200000; /* 200毫秒 */
constexpr int REBOOT_EXIT = 249; /* 退出码: 容器内部触发重启 */
constexpr int NL_BUFSIZE = 8192;
constexpr int BIND_INITIAL_CAP = 4;
constexpr int DEFAULT_TTY_GID = 5;
constexpr int MAX_TRACKED_ENTRIES = 512;

// 运行时路径 - 全部位于 /tmp/<project> 目录下 (使用 tmpfs，重启后丢失)
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
constexpr int PRIV_NOMASK = 1 << 0; // 不使用挂载掩码限制 (/proc, /sys)
constexpr int PRIV_NOCAPS = 1 << 1; // 不丢弃任何内核能力 (capabilities)
constexpr int PRIV_NOSEC  = 1 << 2; // 仅应用最小化的 seccomp 过滤器
constexpr int PRIV_SHARED = 1 << 3; // 根目录挂载传播模式设置为 MS_SHARED
constexpr int PRIV_UNFILT = 1 << 4; // 不阻止访问设备节点 (PTY 除外)
constexpr int PRIV_FULL   = 0xFF;   // 启用上述所有特权

extern "C" {

typedef struct {
  int fd;       // AF_NETLINK / NETLINK_ROUTE 套接字
  uint32_t seq; // 单调递增的序列号
  pid_t pid;    // 用作 nl_portid 的本进程 PID
} nl_ctx_t;

// 终端/TTY 信息 - 每个分配的伪终端对应一个
struct tty_info {
  int master;          // 主设备文件描述符 (保留在父进程/监控进程中)
  int slave;           // 从设备文件描述符 (绑定挂载到容器中)
  char name[PATH_MAX]; // 从设备路径 (例如 /dev/pts/3)
};

struct container_info {
  char name[128];
  pid_t pid;
};

// 容器配置 - 用于替代所有的全局变量
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

// API 声明
bool is_external_lock_active(const char *name);
void cleanup_container_resources(cfg_t *cfg, const bool force_cleanup);
bool is_valid_container_pid(const pid_t pid);
int start_rootfs(cfg_t *cfg);
int stop_rootfs(cfg_t *cfg);
int show_info(cfg_t *cfg,const bool trust_cfg_pid);
int check_requirements_hw(const bool hw_access);
int check_requirements_detailed(void);
void monitor_run(cfg_t *cfg,int sync_pipe_write);
int daemon_run(const bool foreground);
bool daemon_probe(void);
int client_run(int argc,char **argv);
bool is_container_running(char *uuid, pid_t *pid_out);
int collect_active_uuids(char uuids[][UUID_LEN+1],const int max_uuids);
int show_containers(const cfg_t *cfg);
int config_load(const char *config_path,cfg_t *cfg);
int config_save(const char *config_path,cfg_t *cfg);
char *config_auto_path(const char *rootfs_path);
int config_load_by_name(const char *name,cfg_t *cfg);
int config_save_by_name(const char *name,cfg_t *cfg);
void internal_boot(cfg_t *cfg);
bool cgroup_host_is_v2(void);
void cgroup_host_bootstrap(const bool force_cgroupv1);
int setup_cgroups(const bool force_cgroupv1);
void cgroup_cleanup_container(const char *container_name);
void print_cgroup_status(const cfg_t *cfg);
bool cg_word_in_list(const char *list,const char *name);
int cgroup_apply_limits(cfg_t *cfg);
int cgroup_get_usage(const char *container_name,long long *mem,long long *cpu_us,long long *pids);
void apply_jail_mask(const bool hw_access,const int privileged_mask);
void apply_capability_hardening(const bool hw_access,const int privileged_mask);
int seccomp_apply_minimal(const int privileged_mask);
int android_seccomp_setup(const bool block_nested_ns,const int privileged_mask);
int openpty(int *master,int *slave,char *name);
int terminal_create(struct tty_info *tty);
int terminal_set_stdfds(const int fd);
int terminal_make_controlling(const int fd);
int setup_tios(const int fd,struct termios *old);
int setup_dev(const char *rootfs,const bool hw_access,const bool gpu_mode,const int privileged_mask);
int setup_devpts(const bool hw_access);
int fix_host_ptys(void);
int console_monitor_loop(int console_master_fd,pid_t monitor_pid,cfg_t *cfg);
unsigned long get_pid_ns_inode(const pid_t pid);
int virtualize_init(const cfg_t *cfg);
void virtualize_update(const cfg_t *cfg);
const char *detect_fs_type(const char *img_path);
int loop_attach(const char *img_path,char *loop_path_out,const size_t path_size);
void loop_detach(const char *loop_dev);
int get_backing_dev(const char *mnt,char *dev_out,const size_t dev_size);
nl_ctx_t *nl_open(void);
int nl_link_up(nl_ctx_t *ctx,const char *ifname);
bool is_ramfs(const char *path);
int generate_uuid(char *buf,const size_t size);
int parse_os_release(const char *rootfs_path,char *id_out,char *ver_out,const size_t out_size);
int read_proc_environ(const pid_t pid,const char *key,char *value,const size_t size);
int safe_openat_proc(const pid_t pid,const char *subpath,const int flags,const mode_t mode);
void firmware_path_add(const char *fw_path);
void firmware_path_remove(const char *fw_path);
int run_command_quiet(char *const argv[]);
int get_kernel_version(int *major,int *minor);
long get_container_uptime(const pid_t pid);
void format_uptime(const long uptime_sec,char *buf,const size_t size);
int validate_container_name(const char *name);
int reject_container_name(const char *name);
int count_folders(const char *path);
void oom_protect(void);
bool is_mountpoint(const char *path);
int domount(const char *src,const char *tgt,const char *fstype,const unsigned long flags,const char *data);
int bind_mount(const char *src,const char *tgt);
int check_volatile_mode(asc_conf_t *conf);
int setup_volatile_overlay(cfg_t *cfg);
int cleanup_volatile_overlay(asc_rt_t *cfg);
int mount_rootfs_img(const char *img_path,char *mount_point,const size_t mp_size,const char *name);
void unmount_rootfs_img(const char *mount_point,const bool silent);
void write_monitor_debug_log(const char *name,const char *fmt,...);
void print_privileged_warning(const int privileged_mask);
void open_container_log(cfg_t *cfg);
void close_container_log(void);
const char *get_runtime_dir(void);
const char *get_lock_dir(void);
const char *get_logs_dir(void);
int ensure_runtime(void);
void generate_container_name(const char *rootfs_path,char *name,const size_t size);
int mkdir_p(const char *path,const mode_t mode);
int write_file(const char *path,const char *content);
ssize_t write_all(const int fd,const void *buf,const size_t count);
int read_file(const char *path,char *buf,const size_t size);
int remove_recursive(const char *path);
int grep_file(const char *path,const char *pattern);
bool path_has_symlink(const char *path);
bool is_subpath(const char *parent,const char *child);
int force_unlink(const char *path);
void safe_strncpy(char *dst,const char *src,const size_t size);
void sanitize_container_name(const char *name,char *out,const size_t size);
char *resolve_path_arg(const char *path);
void resolve_argv_paths(const int argc,char **argv);
void format_size(const long long bytes,char *buf,const size_t sz);
int collect_pids(pid_t **pids_out,size_t *count_out);
int build_proc_root_path(const pid_t pid,const char *suffix,char *buf,const size_t size);
bool is_container_init(const pid_t pid);
pid_t find_container_init_pid(const char *uuid);

}

#endif