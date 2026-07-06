#ifndef ASC_H
#define ASC_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
#include <ctype.h>
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

constexpr int MIN_KERNEL_MAJOR = 4;
constexpr int MIN_KERNEL_MINOR = 9;
constexpr int UUID_LEN = 32;
constexpr int MAX_CONTAINERS = 1024;
constexpr int STOP_TIMEOUT = 15; /* seconds */
constexpr unsigned int RETRY_DELAY_US = 200000; /* 200ms */
constexpr int REBOOT_EXIT = 249; /* exit code: in-container reboot */
constexpr int NL_BUFSIZE = 8192;
constexpr int BIND_INITIAL_CAP = 4;
constexpr int DEFAULT_TTY_GID = 5;
constexpr int MAX_TRACKED_ENTRIES = 512;

/* Runtime paths - all under /tmp/<project> (tmpfs, gone on reboot) */
#define RUNTIME_DIR "/tmp/asc"
#define RUNTIME_LOCK_SUBDIR "lock"
#define RUNTIME_CONFIG_SUBDIR "config"
#define RUNTIME_LOGS_SUBDIR "logs"
#define RUNTIME_VOLATILE_SUBDIR "volatile"
#define RUNTIME_MNT_SUBDIR "mnt"
#define IMG_MOUNT_ROOT "/mnt/asc"
#define DEFAULT_INIT "/sbin/init"
#define ANDROID_TMPFS_CONTEXT "u:object_r:tmpfs:s0"

/* Common Paths & Patterns */
#define PROC_ROOT_FMT "/proc/%d/root"
#define PROC_CMDLINE_FMT "/proc/%d/cmdline"
#define PROC_STATUS_FMT "/proc/%d/status"
#define PROC_MOUNTINFO "/proc/self/mountinfo"
#define OS_RELEASE "/etc/os-release"
#define FW_PATH_FILE "/sys/module/firmware_class/parameters/path"
#define FORK_MARKER "/run/asc"
#define VPROC_PATH "/run/asc/vproc"

/* File Extensions */
#define EXT_LOCK ".lock"

constexpr int PRIV_NOMASK = 1 << 0; /* No jail masks (/proc, /sys) */
constexpr int PRIV_NOCAPS = 1 << 1; /* No capability drops */
constexpr int PRIV_NOSEC  = 1 << 2; /* Minimal seccomp only */
constexpr int PRIV_SHARED = 1 << 3; /* MS_SHARED root propagation */
constexpr int PRIV_UNFILT = 1 << 4; /* No device node blocking (except PTYs) */
constexpr int PRIV_FULL   = 0xFF;   /* All above */

/* ---------------------------------------------------------------------------
 * Cleanup attribute helpers (RAII-style automatic resource management)
 *
 * Usage:
 *   auto_free char *buf = malloc(1024);    // auto-free on scope exit
 *   auto_fclose FILE *f = fopen(...);      // auto-fclose on scope exit
 *   auto_close int fd = open(...);          // auto-close on scope exit
 *   auto_closedir DIR *d = opendir(...);    // auto-closedir on scope exit
 * ---------------------------------------------------------------------------*/
[[maybe_unused]] static void cfree(void *p) {
  void **pp = p;
  if (*pp) {
    free(*pp);
    *pp = nullptr;
  }
}

[[maybe_unused]] static void cfclose(FILE **f) {
  if (*f) fclose(*f);
}

[[maybe_unused]] static void cclose(const int *fd) {
  if (*fd >= 0) close(*fd);
}

[[maybe_unused]] static void cclosedir(DIR **d) {
  if (*d) closedir(*d);
}

#define _cleanup_(x)  [[gnu::cleanup(x)]]
#define auto_free     _cleanup_(cfree)
#define auto_fclose   _cleanup_(cfclose)
#define auto_close    _cleanup_(cclose)
#define auto_closedir _cleanup_(cclosedir)

struct nl_ctx {
  int fd;       /* AF_NETLINK / NETLINK_ROUTE socket */
  uint32_t seq; /* monotonically increasing sequence number */
  pid_t pid;    /* our PID used as nl_portid */
};

/* Opaque RTNETLINK context - defined in netlink.c */
typedef struct nl_ctx nl_ctx_t;

/* Bind mount entry */
struct bind_mount {
  char src[PATH_MAX];
  char dest[PATH_MAX];
  bool ro; /* 1 = remount read-only after bind */
};

struct config_line {
  char line[2048];
  struct config_line *next;
};

/* Terminal/TTY info - one per allocated PTY */
struct tty_info {
  int master;          /* master fd (stays in parent/monitor) */
  int slave;           /* slave fd (bind-mounted into container) */
  char name[PATH_MAX]; /* slave device path (e.g. /dev/pts/3) */
};

struct container_info {
  char name[128];
  pid_t pid;
};

/* Container configuration - replaces all global variables */
struct config {
  /* Paths */
  char rootfs_img_path[PATH_MAX]; /* --rootfs-img= */
  char container_name[256];       /* --name= (mandatory) */
  bool isolation_network;          /* --isolation_network */

  /* UUID for PID discovery */
  char uuid[UUID_LEN + 1];

  /* Flags */
  bool foreground;      /* --foreground */
  bool hw_access;       /* --hw-access */
  bool gpu_mode;        /* --gpu: mirror GPU nodes into isolated tmpfs /dev */
  bool volatile_mode;   /* --volatile */
  bool reboot_cycle;    /* 1 if we are in a reboot loop */
  bool force_cgroupv1;  /* --force-cgroupv1: use v1 even if v2 is available */
  bool block_nested_ns; /* --block-nested-namespaces: fix VFS deadlock by
                            blocking nested namespace creation */
  int privileged_mask; /* --privileged bitmask */
  bool format_output;   /* --format: machine-parseable output (KEY=VALUE) */
  char prog_name[64];  /* argv[0] for logging */

  /* Runtime state */
  char volatile_dir[PATH_MAX];    /* temporary overlay dir */
  pid_t container_pid;            /* PID 1 of the container (host view) */
  pid_t intermediate_pid;         /* intermediate fork pid */
  char img_mount_point[PATH_MAX]; /* where the .img was mounted */
  char custom_init[PATH_MAX]; /* --init=PATH override (default: /sbin/init) */

  /* Custom bind mounts (dynamically allocated) */
  struct bind_mount *binds;
  int bind_count;
  int bind_capacity;

  /* Configuration persistence */
  char config_file[PATH_MAX];
  bool config_file_specified;
  bool config_file_existed;

  /* Terminal (console + ttys) */
  struct tty_info console;

  /* Unknown config lines (preserved from Android metadata) */
  struct config_line *unknown_head;
  struct config_line *unknown_tail;

  /* Resource limits (0 = unlimited) */
  long long memory_limit; /* bytes */
  long long cpu_quota;    /* us per period */
  long long cpu_period;   /* us (default 100000) */
  long long pids_limit;

  /* Resource virtualization (auto-enabled when limits are set) */
  struct timespec start_time; /* container start time (CLOCK_MONOTONIC) */
  unsigned long ns_inode;     /* PID namespace inode for PID-recycling guard */
};

typedef struct config cfg_t;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

void safe_strncpy(char *dst, const char *src, const size_t size);
char *resolve_path_arg(const char *path);
void resolve_argv_paths(const int argc, char **argv);
long get_container_uptime(const pid_t pid);
void format_uptime(const long uptime_sec, char *buf, const size_t size);
bool is_ramfs(const char *path);
bool is_subpath(const char *parent, const char *child);
int write_file(const char *path, const char *content);
int read_file(const char *path, char *buf, const size_t size);
ssize_t write_all(const int fd, const void *buf, const size_t count);
int generate_uuid(char *buf, const size_t size);
int get_kernel_version(int *major, int *minor);
int mkdir_p(const char *path, mode_t mode);
int remove_recursive(const char *path);
int collect_pids(pid_t **pids_out, size_t *count_out);
int build_proc_root_path(pid_t pid, const char *suffix, char *buf, const size_t size);
int parse_os_release(const char *rootfs_path, char *id_out, char *ver_out,
                     const size_t out_size);
int grep_file(const char *path, const char *pattern);
int read_proc_environ(const pid_t pid, const char *key, char *value, const size_t size);
int safe_openat_proc(const pid_t pid, const char *subpath, const int flags, const mode_t mode);
bool path_has_symlink(const char *path);
void firmware_path_add(const char *fw_path);
void firmware_path_remove(const char *fw_path);
int run_command_quiet(char *const argv[]);
void print_privileged_warning(const int privileged_mask);

void write_monitor_debug_log(const char *name, const char *fmt, ...);
void monitor_run(cfg_t *cfg, int sync_pipe_write);
bool is_external_lock_active(const char *name);
void cleanup_container_resources(cfg_t *cfg,
                                 bool skip_unmount, bool force_cleanup);
void open_container_log(cfg_t *cfg);
void close_container_log(void);
void sort_bind_mounts(cfg_t *cfg);
void sanitize_container_name(const char *name, char *out, const size_t size);
int validate_container_name(const char *name);
int reject_container_name(const char *name);
int parse_and_validate_names(const char *arg, char *out_buf,
                             const size_t out_size);
int multi_stop(const char *raw_names);
int validate_bind_destination(const char *dest);
int count_folders(const char *path);

/* Daemon lifecycle helpers */
typedef void (*child_fn)(int ready_fd, void *user_data);
void oom_protect(void);

int config_load(const char *config_path, cfg_t *cfg);
int config_load_by_name(const char *name, cfg_t *cfg);
int config_save(const char *config_path, cfg_t *cfg);
int config_save_by_name(const char *name, cfg_t *cfg);
void free_config_binds(cfg_t *cfg);
void config_free(cfg_t *cfg);
char *config_auto_path(const char *rootfs_path);

int android_seccomp_setup(bool block_nested_ns, int privileged_mask);
int seccomp_apply_minimal(int privileged_mask);

int domount(const char *src, const char *tgt, const char *fstype,
            const unsigned long flags, const char *data);
int bind_mount(const char *src, const char *tgt);

void apply_jail_mask(bool hw_access, int privileged_mask);
int setup_dev(const char *rootfs, const bool hw_access, const bool gpu_mode,
              const int privileged_mask);
int setup_devpts(const bool hw_access);
int fix_host_ptys(void);
int setup_volatile_overlay(cfg_t *cfg);
int cleanup_volatile_overlay(cfg_t *cfg);
int check_volatile_mode(cfg_t *cfg);

void setup_custom_binds(cfg_t *cfg, const char *rootfs);
int mount_rootfs_img(const char *img_path, char *mount_point, const size_t mp_size,
                     const char *name);

void unmount_rootfs_img(const char *mount_point, const bool silent);
bool is_mountpoint(const char *path);

bool cgroup_host_is_v2(void);
int setup_cgroups(bool force_cgroupv1);
void cgroup_host_bootstrap(bool force_cgroupv1);
/* Remove the entire /sys/fs/cgroup/ds-fork/<name>/ subtree on stop. */
void cgroup_cleanup_container(const char *container_name);
void print_cgroup_status(const cfg_t *cfg);
int cgroup_apply_limits(cfg_t *cfg);
int cgroup_get_usage(const cfg_t *cfg, long long *mem, long long *cpu_us,
                     long long *pids);
void format_size(long long bytes, char *buf, size_t sz);
/* Word-boundary controller name check (used by container.c for subtree_control
 * building; wraps the static ctrl_in_list in cgroup.c). */
bool cg_word_in_list(const char *list, const char *name);

int virtualize_init(const cfg_t *cfg);
void virtualize_update(const cfg_t *cfg);
unsigned long get_pid_ns_inode(pid_t pid);

nl_ctx_t *nl_open(void);
int nl_link_up(nl_ctx_t *ctx, const char *ifname);

int openpty(int *master, int *slave, char *name);
int terminal_create(struct tty_info *tty);
int terminal_set_stdfds(int fd);
int terminal_make_controlling(int fd);
int setup_tios(int fd, struct termios *old);

int console_monitor_loop(int console_master_fd, pid_t monitor_pid,
                         cfg_t *cfg);

const char *get_runtime_dir(void);
const char *get_lock_dir(void);
const char *get_logs_dir(void);
int ensure_runtime(void);

void generate_container_name(const char *rootfs_path, char *name, const size_t size);
bool is_container_running(const cfg_t *cfg, pid_t *pid_out);
bool is_container_init(const pid_t pid);
int count_running_containers(char *first_name, const size_t size);
pid_t find_container_init_pid(const char *uuid);
int collect_active_uuids(char uuids[][UUID_LEN + 1], int max_uuids);
int show_containers(const cfg_t *cfg);
int scan_containers(void);

void apply_capability_hardening(bool hw_access, int privileged_mask);

void internal_boot(cfg_t *cfg);

bool is_valid_container_pid(pid_t pid);
int start_rootfs(cfg_t *cfg);
int stop_rootfs(cfg_t *cfg, bool skip_unmount);
int show_info(cfg_t *cfg, bool trust_cfg_pid);
int show_container_usage(cfg_t *cfg);
int restart_rootfs(cfg_t *cfg);

int check_requirements_hw(const bool hw_access);
int check_requirements_detailed(void);

int daemon_run(bool foreground);
int client_run(int argc, char **argv);
bool daemon_probe(void);

void loop_detach(const char *loop_dev);
int loop_attach(const char *img_path, char *loop_path_out, size_t path_size);
int get_backing_dev(const char *mnt, char *dev_out, size_t dev_size);
const char *detect_fs_type(const char *img_path);
int force_unlink(const char *path);

#endif /* ASC_H */
