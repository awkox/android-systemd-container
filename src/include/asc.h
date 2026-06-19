/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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

/* ---------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------------*/

#define MIN_KERNEL_MAJOR 4
#define MIN_KERNEL_MINOR 9
#define UUID_LEN 32
#define MAX_CONTAINERS 1024
#define STOP_TIMEOUT 15 /* seconds */
#define PID_SCAN_RETRIES 20
#define PID_SCAN_DELAY_US 200000 /* 200ms */
#define RETRY_DELAY_US 200000    /* 200ms */
#define REBOOT_EXIT 249          /* exit code: in-container reboot */

/* Runtime paths - all under /tmp/<project> (tmpfs, gone on reboot) */
#define RUNTIME_DIR "/tmp/" PROJECT_NAME
#define RUNTIME_LOCK_SUBDIR "lock"
#define RUNTIME_CONFIG_SUBDIR "config"
#define RUNTIME_LOGS_SUBDIR "logs"
#define RUNTIME_VOLATILE_SUBDIR "volatile"
#define RUNTIME_MNT_SUBDIR "mnt"
#define IMG_MOUNT_ROOT "/mnt/" PROJECT_NAME
#define MAX_MOUNT_TRIES 1024
#define BIND_INITIAL_CAP 4
#define DEFAULT_INIT "/sbin/init"
#define ANDROID_TMPFS_CONTEXT "u:object_r:tmpfs:s0"

/* Device nodes to create in container /dev (when using tmpfs) */
#define CONTAINER_MARKER PROJECT_NAME

/* Common Paths & Patterns */
#define PROC_ROOT_FMT "/proc/%d/root"
#define PROC_CMDLINE_FMT "/proc/%d/cmdline"
#define PROC_STATUS_FMT "/proc/%d/status"
#define PROC_MOUNTINFO "/proc/self/mountinfo"
#define OS_RELEASE "/etc/os-release"
#define FW_PATH_FILE "/sys/module/firmware_class/parameters/path"
#define FORK_MARKER "/run/" PROJECT_NAME

/* Hardening constants */
#define DEFAULT_TTY_GID 5
#define MAX_TRACKED_ENTRIES 512

/* File Extensions */
#define EXT_LOCK ".lock"

/* Colors for output */
#define C_RESET "\033[0m"
#define C_RED "\033[1;31m"
#define C_GREEN "\033[1;32m"
#define C_YELLOW "\033[1;33m"
#define C_BLUE "\033[1;34m"
#define C_CYAN "\033[1;36m"
#define C_WHITE "\033[1;37m"
#define C_DIM "\033[2m"
#define C_BOLD "\033[1m"

/* ---------------------------------------------------------------------------
 * Logging macros & Centralized Engine
 * ---------------------------------------------------------------------------*/

extern int log_silent;
extern char log_container_name[256];
extern int log_container_fd;

void log_internal(const char *prefix, const char *color, int is_err,
                  const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void die_internal(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void rotate_log(const char *path, size_t max_size);
int check_ns(int flag, const char *name);

#define log_info(fmt, ...) log_internal("+", C_GREEN, 0, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_warn(fmt, ...) log_internal("!", C_YELLOW, 1, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_error(fmt, ...) log_internal("-", C_RED, 1, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_die(fmt, ...) die_internal(fmt __VA_OPT__(,) __VA_ARGS__)

/* ---------------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------------*/

/* Networking modes */

enum net_mode {
  NET_HOST = 0, /* share host network namespace (default) */
  NET_NONE,     /* isolated netns with loopback only       */
};

/* Opaque RTNETLINK context - defined in netlink.c */
typedef struct nl_ctx nl_ctx_t;

/* Bind mount entry */
struct bind_mount {
  char src[PATH_MAX];
  char dest[PATH_MAX];
  int ro; /* 1 = remount read-only after bind */
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

/* Container configuration - replaces all global variables */
/* ---------------------------------------------------------------------------
 * Privileged Mode Flags
 * ---------------------------------------------------------------------------*/
#define PRIV_NOMASK (1 << 0)     /* No jail masks (/proc, /sys) */
#define PRIV_NOCAPS (1 << 1)     /* No capability drops */
#define PRIV_NOSEC (1 << 2)      /* Minimal seccomp only */
#define PRIV_SHARED (1 << 3)     /* MS_SHARED root propagation */
#define PRIV_UNFILTERED (1 << 4) /* No device node blocking (except PTYs) */
#define PRIV_FULL (0xFF)         /* All above */

struct config {
  /* Paths */
  char rootfs_img_path[PATH_MAX]; /* --rootfs-img= */
  char container_name[256];       /* --name= (mandatory) */
  enum net_mode net_mode;         /* --net=host|none */

  /* UUID for PID discovery */
  char uuid[UUID_LEN + 1];

  /* Flags */
  int foreground;      /* --foreground */
  int hw_access;       /* --hw-access */
  int gpu_mode;        /* --gpu: mirror GPU nodes into isolated tmpfs /dev */
  int volatile_mode;   /* --volatile */
  int android_storage; /* --enable-android-storage */
  int reboot_cycle;    /* 1 if we are in a reboot loop */
  int force_cgroupv1;  /* --force-cgroupv1: use v1 even if v2 is available */
  int block_nested_ns; /* --block-nested-namespaces: fix VFS deadlock by
                            blocking nested namespace creation */
  int privileged_mask; /* --privileged bitmask */
  int format_output;   /* --format: machine-parseable output (KEY=VALUE) */
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
  int config_file_specified;
  int config_file_existed;

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

/* ---------------------------------------------------------------------------
 * utils.c
 * ---------------------------------------------------------------------------*/

void safe_strncpy(char *dst, const char *src, size_t size);
char *resolve_path_arg(const char *path);
void resolve_argv_paths(int argc, char **argv);
long get_container_uptime(pid_t pid);
void format_uptime(long uptime_sec, char *buf, size_t size);
int is_ramfs(const char *path);
int is_subpath(const char *parent, const char *child);
int write_file(const char *path, const char *content);
int read_file(const char *path, char *buf, size_t size);
ssize_t write_all(int fd, const void *buf, size_t count);
int generate_uuid(char *buf, size_t size);
int get_kernel_version(int *major, int *minor);
int mkdir_p(const char *path, mode_t mode);
int remove_recursive(const char *path);
int collect_pids(pid_t **pids_out, size_t *count_out);
int build_proc_root_path(pid_t pid, const char *suffix, char *buf, size_t size);
int parse_os_release(const char *rootfs_path, char *id_out, char *ver_out,
                     size_t out_size);
int grep_file(const char *path, const char *pattern);
int read_proc_environ(pid_t pid, const char *key, char *value, size_t size);
int safe_openat_proc(pid_t pid, const char *subpath, int flags, mode_t mode);
int path_has_symlink(const char *path);
void firmware_path_add(const char *fw_path);
void firmware_path_remove(const char *fw_path);
int run_command_quiet(char *const argv[]);
void print_privileged_warning(int privileged_mask);

void write_monitor_debug_log(const char *name, const char *fmt, ...);
void monitor_run(struct config *cfg, int sync_pipe_write);
int is_external_lock_active(const char *name);
void cleanup_container_resources(struct config *cfg,
                                 int skip_unmount, int force_cleanup);
void open_container_log(struct config *cfg);
void close_container_log(void);
void sort_bind_mounts(struct config *cfg);
void sanitize_container_name(const char *name, char *out, size_t size);
int validate_container_name(const char *name);
int reject_container_name(const char *name);
int parse_and_validate_names(const char *optarg, char *out_buf,
                             size_t out_size);
int multi_stop(const char *raw_names);
int validate_bind_destination(const char *dest);
int count_folders(const char *path);

/* Daemon lifecycle helpers */
typedef void (*child_fn)(int ready_fd, void *user_data);
void oom_protect(void);

/* ---------------------------------------------------------------------------
 * config.c
 * ---------------------------------------------------------------------------*/

int config_load(const char *config_path, struct config *cfg);
int config_load_by_name(const char *name, struct config *cfg);
int config_save(const char *config_path, struct config *cfg);
int config_save_by_name(const char *name, struct config *cfg);
int config_add_bind(struct config *cfg, const char *src, const char *dest,
                    int ro);
void free_config_binds(struct config *cfg);
void free_config_unknown_lines(struct config *cfg);
void config_free(struct config *cfg);
char *config_auto_path(const char *rootfs_path);
void parse_privileged(const char *value, struct config *cfg);

/* ---------------------------------------------------------------------------
 * android.c
 * ---------------------------------------------------------------------------*/

int is_android(void);
int android_setup_storage(const char *rootfs_path);
int android_seccomp_setup(int block_nested_ns, int privileged_mask);
int seccomp_apply_minimal(int privileged_mask);

/* ---------------------------------------------------------------------------
 * mount.c
 * ---------------------------------------------------------------------------*/

int domount(const char *src, const char *tgt, const char *fstype,
            unsigned long flags, const char *data);
int bind_mount(const char *src, const char *tgt);
int apply_jail_mask(int hw_access, int privileged_mask);
int setup_dev(const char *rootfs, int hw_access, int gpu_mode,
              int privileged_mask);
int create_devices(const char *rootfs);
int setup_devpts(int hw_access);
int fix_host_ptys(void);
int setup_volatile_overlay(struct config *cfg);
int cleanup_volatile_overlay(struct config *cfg);
int check_volatile_mode(struct config *cfg);
int setup_custom_binds(struct config *cfg, const char *rootfs);
int mount_rootfs_img(const char *img_path, char *mount_point, size_t mp_size,
                     const char *name);
int unmount_rootfs_img(const char *mount_point, int silent);
int is_mountpoint(const char *path);

/* ---------------------------------------------------------------------------
 * cgroup.c
 * ---------------------------------------------------------------------------*/

int cgroup_kernel_supports_v2(void);
int cgroup_host_is_v2(void);
int setup_cgroups(int force_cgroupv1);
void cgroup_host_bootstrap(int force_cgroupv1);
/* Remove the entire /sys/fs/cgroup/ds-fork/<name>/ subtree on stop. */
void cgroup_cleanup_container(const char *container_name);
void print_cgroup_status(struct config *cfg);
int cgroup_apply_limits(struct config *cfg);
int cgroup_get_usage(struct config *cfg, long long *mem, long long *cpu_us,
                     long long *pids);
long long parse_size(const char *str);
void format_size(long long bytes, char *buf, size_t sz);
/* Word-boundary controller name check (used by container.c for subtree_control
 * building; wraps the static ctrl_in_list in cgroup.c). */
int cg_word_in_list(const char *list, const char *name);

/* ---------------------------------------------------------------------------
 * virtualize.c
 * ---------------------------------------------------------------------------*/

int virtualize_init(struct config *cfg);
void virtualize_update(struct config *cfg);
unsigned long get_pid_ns_inode(pid_t pid);

/* ---------------------------------------------------------------------------
 * hardware.c
 * ---------------------------------------------------------------------------*/

void mirror_gpu_nodes(const char *dev_path);

/* ---------------------------------------------------------------------------
 * netlink.c (minimal - link up only)
 * ---------------------------------------------------------------------------*/

nl_ctx_t *nl_open(void);
void nl_close(nl_ctx_t *ctx);
int nl_get_ifindex(nl_ctx_t *ctx, const char *ifname);
int nl_link_up(nl_ctx_t *ctx, const char *ifname);

/* ---------------------------------------------------------------------------
 * terminal.c
 * ---------------------------------------------------------------------------*/

int openpty(int *master, int *slave, char *name);
int terminal_create(struct tty_info *tty);
int terminal_set_stdfds(int fd);
int terminal_make_controlling(int fd);
int setup_tios(int fd, struct termios *old);

/* ---------------------------------------------------------------------------
 * console.c
 * ---------------------------------------------------------------------------*/

int console_monitor_loop(int console_master_fd, pid_t monitor_pid,
                         struct config *cfg);

/* ---------------------------------------------------------------------------
 * pid.c
 * ---------------------------------------------------------------------------*/

const char *get_runtime_dir(void);
const char *get_lock_dir(void);
const char *get_logs_dir(void);
int ensure_runtime(void);
int generate_container_name(const char *rootfs_path, char *name, size_t size);
int is_container_running(struct config *cfg, pid_t *pid_out);
int is_container_init(pid_t pid);
int metadata_sync(pid_t pid);
int count_running_containers(char *first_name, size_t size);
pid_t find_container_init_pid(const char *uuid);
int collect_active_uuids(char uuids[][UUID_LEN + 1], int max_uuids);
int show_containers(struct config *cfg);
int scan_containers(void);

/* ---------------------------------------------------------------------------
 * boot.c
 * ---------------------------------------------------------------------------*/

void apply_capability_hardening(int hw_access, int privileged_mask);
int internal_boot(struct config *cfg);

/* ---------------------------------------------------------------------------
 * container.c
 * ---------------------------------------------------------------------------*/

int is_valid_container_pid(pid_t pid);
int start_rootfs(struct config *cfg);
int stop_rootfs(struct config *cfg, int skip_unmount);
int stop_rootfs_with_timeout(struct config *cfg, int skip_unmount,
                             int timeout_seconds);
int show_info(struct config *cfg, int trust_cfg_pid);
int show_container_usage(struct config *cfg);
int restart_rootfs(struct config *cfg);
int restart_rootfs_with_timeout(struct config *cfg, int timeout_seconds);

/* ---------------------------------------------------------------------------
 * check.c
 * ---------------------------------------------------------------------------*/

int is_dangerous_node(const char *name);
int check_requirements_hw(int hw_access);
int check_requirements_detailed(void);

/* ---------------------------------------------------------------------------
 * daemon.c - daemon, client, and probe entry points
 * ---------------------------------------------------------------------------*/

int daemon_run(int foreground);
int client_run(int argc, char **argv);
int daemon_probe(void);

#endif /* ASC_H */
