/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ds-fork.h"

/* ---------------------------------------------------------------------------
 * Static status variables
 * ---------------------------------------------------------------------------*/

static int is_root = 0;

/* ---------------------------------------------------------------------------
 * Output buffering (for one-shot terminal output)
 * ---------------------------------------------------------------------------*/

#define CHECK_BUF_SIZE 16384
static char check_buf[CHECK_BUF_SIZE];
static size_t check_buf_pos = 0;

static void check_append(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(check_buf + check_buf_pos, CHECK_BUF_SIZE - check_buf_pos,
                    fmt, args);
  va_end(args);

  if (n > 0) {
    if (check_buf_pos + n < CHECK_BUF_SIZE) {
      check_buf_pos += n;
    } else {
      check_buf_pos = CHECK_BUF_SIZE - 1; /* Truncate if full */
    }
  }
}

/* ---------------------------------------------------------------------------
 * Requirement checks
 * ---------------------------------------------------------------------------*/

static int check_root(void) {
  is_root = (getuid() == 0);
  return is_root;
}

int check_ns(int flag, const char *name) {
  /* 1. Fast check for kernel support via /proc */
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
  if (access(path, F_OK) != 0)
    return 0;

  /* 2. Functional check: Try to actually unshare.
   * We fork because unshare() affects the current process. */
  pid_t p = fork();
  if (p < 0)
    return 0;

  if (p == 0) {
    if (unshare(flag) < 0) {
      _exit(1);
    }
    _exit(0);
  }

  int status;
  waitpid(p, &status, 0);
  return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int check_pivot_root(void) {
  /* Probe for pivot_root syscall presence without actually executing it
   * with dangerous arguments. We check if the syscall is implemented
   * by passing invalid pointers (-1) or NULLs; if it returns ENOSYS,
   * it's missing. If it returns EFAULT or EINVAL, it exists. */
  if (syscall(__NR_pivot_root, NULL, NULL) < 0 && errno == ENOSYS)
    return 0;
  return 1;
}

static int check_loop(void) { return access("/dev/loop-control", F_OK) == 0; }

static int check_seccomp(void) {
  /* Probe for SECCOMP_MODE_FILTER support */
  return (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 || errno == EINVAL);
}

static int check_kernel_version_supported(void) {
  int major = 0, minor = 0;
  if (get_kernel_version(&major, &minor) < 0)
    return 0;
  if (major < MIN_KERNEL_MAJOR)
    return 0;
  if (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)
    return 0;
  return 1;
}

/* ---------------------------------------------------------------------------
 * Minimal check for 'start' (used internaly)
 * ---------------------------------------------------------------------------*/

int check_requirements_hw(int hw_access) {
  int missing = 0;

  if (!check_root()) {
    log_error("Must be run as root");
    log_info("This tool requires root privileges for namespace and mount "
             "operations.");
    missing++;
  }

  /* devtmpfs is only needed for --hw-access; without it we use tmpfs */
  if (hw_access && grep_file("/proc/filesystems", "devtmpfs") == 0) {
    log_warn("Hardware access mode is active but this kernel does not support "
             "devtmpfs. GPU and hardware nodes may not be available.");
  }

  /* Functional namespace checks */
  if (!check_ns(CLONE_NEWNS, "mnt")) {
    log_error("Mount namespace is not supported by the kernel");
    log_info("This is a REQUIRED feature for filesystem isolation.");
    missing++;
  }
  if (!check_ns(CLONE_NEWPID, "pid")) {
    log_error("PID namespace is not supported by the kernel");
    log_info("This is a REQUIRED feature for process isolation.");
    missing++;
  }
  if (!check_ns(CLONE_NEWUTS, "uts")) {
    log_error("UTS namespace is not supported by the kernel");
    log_info("This is a REQUIRED feature for hostname isolation.");
    missing++;
  }
  if (!check_ns(CLONE_NEWIPC, "ipc")) {
    log_error("IPC namespace is not supported by the kernel");
    log_info("This is a REQUIRED feature for IPC isolation.");
    missing++;
  }

  if (!check_pivot_root()) {
    log_error("pivot_root syscall is not supported on the current filesystem");
    log_info(PROJECT_NAME " requires a rootfs that supports pivot_root (not "
                          "ramfs).");
    missing++;
  }

  if (!check_kernel_version_supported()) {
    log_error("Kernel version is too old");
    log_info(PROJECT_NAME " requires at least Linux %d.%d.0.", MIN_KERNEL_MAJOR,
             MIN_KERNEL_MINOR);
    missing++;
  }

  if (missing > 0) {
    printf("\n");
    log_error("Missing %d required feature(s) - cannot proceed", missing);
    log_info("Please run " C_BOLD "./" PROJECT_NAME " check" C_RESET
             " for a full diagnostic report.");
    return -1;
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * Detailed 'check' command
 * ---------------------------------------------------------------------------*/

/* Helper to check and close an FD-based feature probe */
static int check_fd_feature(int fd) {
  if (fd >= 0) {
    close(fd);
    return 1;
  }
  return 0;
}

void print_check(const char *name, const char *desc, int status,
                 const char *level) {
  const char *c_sym =
      status ? C_GREEN : (strcmp(level, "MUST") == 0 ? C_RED : C_YELLOW);
  const char *sym = status ? "✓" : "✗";

  check_append("  [%s%s%s] %s\n", c_sym, sym, C_RESET, name);
  if (!status) {
    check_append("      " C_DIM "%s" C_RESET "\n", desc);
    if (strstr(name, "namespace") || strstr(name, "Root")) {
      if (!is_root)
        check_append("      " C_YELLOW
                     "(Note: Namespace checks require root privileges)" C_RESET
                     "\n");
    }
  }
}

int check_requirements_detailed(void) {
  check_buf_pos = 0;
  check_buf[0] = '\0';

  check_root();

  check_append("\n" C_BOLD PROJECT_NAME
               " v%s — Checking system requirements..." C_RESET "\n\n",
               RUNTIME_VERSION);

  int missing_must = 0;

  /* MUST HAVE */
  check_append(C_BOLD "[MUST HAVE]" C_RESET
                      "\nThese features are required for " PROJECT_NAME
                      " to work:\n\n");

  if (!is_root)
    missing_must++;
  print_check("Root privileges",
              "Running as root user (required for container operations)",
              is_root, "MUST");

  char kver_desc[128];
  snprintf(kver_desc, sizeof(kver_desc),
           "Linux kernel version %d.%d.0 or later", MIN_KERNEL_MAJOR,
           MIN_KERNEL_MINOR);
  int kver_ok = check_kernel_version_supported();
  if (!kver_ok)
    missing_must++;
  print_check("Linux version", kver_desc, kver_ok, "MUST");

  int has_pid_ns = check_ns(CLONE_NEWPID, "pid");
  if (!has_pid_ns)
    missing_must++;
  print_check("PID namespace", "Process ID namespace isolation", has_pid_ns,
              "MUST");

  int has_mnt_ns = check_ns(CLONE_NEWNS, "mnt");
  if (!has_mnt_ns)
    missing_must++;
  print_check("Mount namespace", "Filesystem namespace isolation", has_mnt_ns,
              "MUST");

  int has_uts_ns = check_ns(CLONE_NEWUTS, "uts");
  if (!has_uts_ns)
    missing_must++;
  print_check("UTS namespace", "Hostname/domainname isolation", has_uts_ns,
              "MUST");

  int has_ipc_ns = check_ns(CLONE_NEWIPC, "ipc");
  if (!has_ipc_ns)
    missing_must++;
  print_check("IPC namespace", "Inter-process communication isolation",
              has_ipc_ns, "MUST");

  int has_pivot = check_pivot_root();
  if (!has_pivot)
    missing_must++;
  print_check("pivot_root syscall", "Kernel support for the pivot_root syscall",
              has_pivot, "MUST");

  int has_proc_fs = access("/proc/self", F_OK) == 0;
  if (!has_proc_fs)
    missing_must++;
  print_check("/proc filesystem", "Proc filesystem mount support", has_proc_fs,
              "MUST");

  int has_sys_fs = access("/sys/kernel", F_OK) == 0;
  if (!has_sys_fs)
    missing_must++;
  print_check("/sys filesystem", "Sys filesystem mount support", has_sys_fs,
              "MUST");

  int has_seccomp = check_seccomp();
  if (!has_seccomp)
    missing_must++;
  print_check("Seccomp support", "Kernel support for Seccomp (Bypass Mode)",
              has_seccomp, "MUST");

  /* RECOMMENDED */
  check_append("\n" C_BOLD "[RECOMMENDED]" C_RESET
               "\nThese features improve functionality but are not strictly "
               "required:\n\n");

  print_check("epoll support", "Efficient I/O event notification",
              check_fd_feature(epoll_create1(0)), "OPT");

  sigset_t mask;
  sigemptyset(&mask);
  print_check("signalfd support", "Signal handling via file descriptors",
              check_fd_feature(signalfd(-1, &mask, 0)), "OPT");

  print_check("PTY support", "Unix98 PTY support",
              access("/dev/ptmx", F_OK) == 0, "OPT");

  print_check("devpts support", "Virtual terminal filesystem support",
              access("/dev/pts", F_OK) == 0, "OPT");

  print_check("Loop device", "Required for rootfs.img mounting", check_loop(),
              "OPT");

  print_check("ext4 filesystem", "Ext4 filesystem support",
              grep_file("/proc/filesystems", "ext4"), "OPT");

  print_check("Cgroup v2 support", "Unified Control Group hierarchy support",
              grep_file("/proc/filesystems", "cgroup2"), "OPT");

  print_check("Cgroup namespace", "Control Group namespace isolation",
              check_ns(CLONE_NEWCGROUP, "cgroup"), "OPT");

  int has_devtmpfs = grep_file("/proc/filesystems", "devtmpfs");
  print_check(
      "devtmpfs support",
      "Required for hardware access mode; tmpfs fallback used otherwise",
      has_devtmpfs, "OPT");

  /* OPTIONAL */
  check_append("\n" C_BOLD "[OPTIONAL]" C_RESET
               "\nThese features are optional and only used for specific "
               "functionality:\n\n");

  print_check("FUSE support", "Filesystem in Userspace support",
              access("/dev/fuse", F_OK) == 0 ||
                  grep_file("/proc/filesystems", "fuse"),
              "OPT");
  print_check("TUN/TAP support", "Virtual network device support",
              access("/dev/net/tun", F_OK) == 0, "OPT");
  print_check("OverlayFS support", "Required for --volatile mode",
              grep_file("/proc/filesystems", "overlay"), "OPT");
  print_check("Network namespace", "Network namespace isolation for --net=none",
              check_ns(CLONE_NEWNET, "net"), "OPT");

  /* HARDENING */
  check_append("\n" C_BOLD "[HARDENING]" C_RESET
               "\nThese checks are not required for " PROJECT_NAME " to work, "
               "but are recommended for hardened kernels:\n\n");

  int has_user_ns = access("/proc/self/ns/user", F_OK) == 0;
  print_check("CONFIG_USER_NS disabled",
              "Kernel exposes user namespace support, which " PROJECT_NAME " "
              "does not require and hardened kernels should disable",
              !has_user_ns, "OPT");

  /* FINAL SUMMARY */
  check_append("\n" C_BOLD "Summary:" C_RESET "\n\n");
  if (missing_must > 0)
    check_append("  [" C_RED "✗" C_RESET
                 "] %d required feature(s) missing - " PROJECT_NAME
                 " will not work\n",
                 missing_must);
  else
    check_append("  [" C_GREEN "✓" C_RESET "] All required features found!\n");

  if (!is_root) {
    check_append(C_BOLD C_YELLOW "\n[!] Warning: You are not root. Some checks "
                                 "may be inaccurate.\n" C_RESET);
  }
  check_append("\n");

  /* One-shot output to terminal */
  fwrite(check_buf, 1, check_buf_pos, stdout);
  fflush(stdout);

  return 0;
}
