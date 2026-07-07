#include "asc.h"

static bool is_root = false;

#define CHECK_BUF_SIZE (16 * 1024)
static char check_buf[CHECK_BUF_SIZE];
static size_t check_buf_pos = 0;

static void check_append(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const int n = vsnprintf(check_buf + check_buf_pos, CHECK_BUF_SIZE - check_buf_pos,
                    fmt, args);
  va_end(args);

  if (n > 0) {
    if (check_buf_pos + n < CHECK_BUF_SIZE) {
      check_buf_pos += n;
    } else {
      check_buf_pos = CHECK_BUF_SIZE - 1; /* 如果满了则截断 */
    }
  }
}

static bool check_root(void) {
  is_root = getuid() == 0;
  return is_root;
}

static bool check_ns(const int flag, const char *name) {
  /* 1. 通过 /proc 快速检查内核支持 */
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
  if (access(path, F_OK) != 0)
    return false;

  /* 2. 功能性检查：尝试实际执行 unshare。
   * 因为 unshare() 会影响当前进程，所以我们使用 fork() 来隔离。 */
  const pid_t p = fork();
  if (p < 0)
    return false;

  if (p == 0) {
    if (unshare(flag) < 0) {
      _exit(1);
    }
    _exit(0);
  }

  int status;
  waitpid(p, &status, 0);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool check_pivot_root(void) {
  /* 
   * 探测 pivot_root 系统调用是否存在，而不实际执行携带危险参数的调用。
   * 我们通过传递无效指针 (nullptr) 检查该系统调用是否已实现；
   * 如果返回 ENOSYS，说明内核未提供。如果返回 EFAULT 或 EINVAL，说明其存在。 
   */
  if (syscall(__NR_pivot_root, nullptr, nullptr) < 0 && errno == ENOSYS)
    return false;
  return true;
}

static bool check_loop(void) {
  return access("/dev/loop-control", F_OK) == 0;
}

static bool check_seccomp(void) {
  /* 探测内核对 SECCOMP_MODE_FILTER 的支持 */
  return prctl(PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 || errno == EINVAL;
}

static bool check_kernel_version_supported(void) {
  int major = 0, minor = 0;
  if (get_kernel_version(&major, &minor) < 0)
    return false;
  if (major < MIN_KERNEL_MAJOR)
    return false;
  if (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)
    return false;
  return true;
}

int check_requirements_hw(const bool hw_access) {
  int missing = 0;

  if (!check_root()) {
    log_error("必须以 root 用户身份运行");
    log_info("本工具需要 root 权限来进行命名空间和挂载操作。");
    missing++;
  }

  /* 只有在启用了 --hw-access 模式时才需要 devtmpfs，否则我们使用私有 tmpfs */
  if (hw_access && grep_file("/proc/filesystems", "devtmpfs") == 0) {
    log_warn("已激活硬件直通模式，但您的内核不支持 devtmpfs。\n"
             "部分 GPU 和硬件设备节点可能无法可用。");
  }

  /* 功能性命名空间检查 */
  if (!check_ns(CLONE_NEWNS, "mnt")) {
    log_error("当前内核不支持 Mount 命名空间 (挂载隔离)");
    log_info("这是实现文件系统隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWPID, "pid")) {
    log_error("当前内核不支持 PID 命名空间 (进程隔离)");
    log_info("这是实现进程环境隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWUTS, "uts")) {
    log_error("当前内核不支持 UTS 命名空间 (主机名隔离)");
    log_info("这是实现主机名隔离的一项【必须】功能。");
    missing++;
  }
  if (!check_ns(CLONE_NEWIPC, "ipc")) {
    log_error("当前内核不支持 IPC 命名空间 (进程间通信隔离)");
    log_info("这是实现 IPC 隔离的一项【必须】功能。");
    missing++;
  }

  if (!check_pivot_root()) {
    log_error("当前内核不支持 pivot_root 系统调用");
    log_info(PROJECT_NAME " 必须在支持 pivot_root(而非 ramfs) 的根文件系统上运行。");
    missing++;
  }

  if (!check_kernel_version_supported()) {
    log_error("Linux 内核版本太老");
    log_info(PROJECT_NAME " 至少需要 Linux %d.%d.0 版本的内核。", MIN_KERNEL_MAJOR,
             MIN_KERNEL_MINOR);
    missing++;
  }

  if (missing > 0) {
    printf("\n");
    log_error("缺少 %d 项【必须】功能 - 无法继续启动过程", missing);
    log_info("请运行 './" PROJECT_NAME " check' 来查看完整的系统诊断报告。");
    return -1;
  }

  return 0;
}

/* 辅助函数：用于检查基于 FD(文件描述符) 的功能探测，并在成功后自动关闭 FD */
static bool check_fd_feature(const int fd) {
  if (fd >= 0) {
    close(fd);
    return true;
  }
  return false;
}

static void print_check(const char *name, const char *desc, const bool status) {
  const char *sym = status ? "✓" : "✗";

  check_append("  [%s] %s\n", sym, name);
  if (!status) {
    check_append("      %s\n", desc);
    if (strstr(name, "namespace") || strstr(name, "Root")) {
      if (!is_root)
        check_append("      (注意：命名空间相关的检查必须在 root 权限下进行)\n");
    }
  }
}

int check_requirements_detailed(void) {
  check_buf_pos = 0;
  check_buf[0] = '\0';
  int missing_must = 0;

  check_root();

  check_append("\n正在检查系统环境与要求...\n\n");

  /* 必须拥有的特性 (MUST HAVE) */
  check_append("[必须功能]\n"
    "以下内核功能是 " PROJECT_NAME " 正常运行所必需的：\n\n");

  if (!is_root)
    missing_must++;
  print_check("Root 权限",
              "以 root 用户身份运行（进行容器内核操作需要）",
              is_root);

  char kver_desc[128];
  snprintf(kver_desc, sizeof(kver_desc),
           "Linux 内核版本大于或等于 %d.%d.0", MIN_KERNEL_MAJOR,
           MIN_KERNEL_MINOR);
  const bool kver_ok = check_kernel_version_supported();
  if (!kver_ok)
    missing_must++;
  print_check("Linux 内核版本", kver_desc, kver_ok);

  const bool has_pid_ns = check_ns(CLONE_NEWPID, "pid");
  if (!has_pid_ns)
    missing_must++;
  print_check("PID 命名空间", "提供进程 ID 隔离", has_pid_ns);

  const bool has_mnt_ns = check_ns(CLONE_NEWNS, "mnt");
  if (!has_mnt_ns)
    missing_must++;
  print_check("Mount 命名空间", "提供挂载点与文件系统隔离", has_mnt_ns);

  const bool has_uts_ns = check_ns(CLONE_NEWUTS, "uts");
  if (!has_uts_ns)
    missing_must++;
  print_check("UTS 命名空间", "提供主机名(Hostname)隔离", has_uts_ns);

  const bool has_ipc_ns = check_ns(CLONE_NEWIPC, "ipc");
  if (!has_ipc_ns)
    missing_must++;
  print_check("IPC 命名空间", "提供进程间通信隔离", has_ipc_ns);

  const bool has_pivot = check_pivot_root();
  if (!has_pivot)
    missing_must++;
  print_check("pivot_root 系统调用", "内核支持将根目录挂载点进行无缝切换", has_pivot);

  const bool has_proc_fs = access("/proc/self", F_OK) == 0;
  if (!has_proc_fs)
    missing_must++;
  print_check("/proc 文件系统", "支持挂载 Proc 虚拟文件系统", has_proc_fs);

  const bool has_sys_fs = access("/sys/kernel", F_OK) == 0;
  if (!has_sys_fs)
    missing_must++;
  print_check("/sys 文件系统", "支持挂载 Sys 虚拟文件系统", has_sys_fs);

  const bool has_seccomp = check_seccomp();
  if (!has_seccomp)
    missing_must++;
  print_check("Seccomp 内核机制", "内核支持 Seccomp (Bypass/过滤模式)", has_seccomp);

  /* 建议支持的特性 (RECOMMENDED) */
  check_append("\n[建议功能]\n"
               "以下功能可以提供更好的使用体验，但并非必需项：\n\n");

  print_check("epoll 支持", "高效的 I/O 事件通知机制", check_fd_feature(epoll_create1(0)));

  sigset_t mask;
  sigemptyset(&mask);
  print_check("signalfd 支持", "通过文件描述符处理异步信号",
              check_fd_feature(signalfd(-1, &mask, 0)));

  print_check("PTY 伪终端支持", "Unix98 规范的伪终端(PTY)支持", access("/dev/ptmx", F_OK) == 0);

  print_check("devpts 支持", "提供虚拟终端的挂载点文件系统", access("/dev/pts", F_OK) == 0);

  print_check("Loop 回环设备", "通过 rootfs.img 启动时需要用作块设备挂载", check_loop());

  print_check("ext4 文件系统", "原生 Ext4 文件系统支持", grep_file("/proc/filesystems", "ext4"));

  print_check("Cgroup v2 支持", "统一架构下的控制组(Cgroup)支持", grep_file("/proc/filesystems", "cgroup2"));

  print_check("Cgroup 命名空间", "提供控制组目录视图隔离", check_ns(CLONE_NEWCGROUP, "cgroup"));

  const bool has_devtmpfs = grep_file("/proc/filesystems", "devtmpfs");
  print_check("devtmpfs 支持", "硬件访问模式必须支持；如果不支持，默认回退使用私有 tmpfs", has_devtmpfs);

  /* 可选特性 (OPTIONAL) */
  check_append("\n[可选功能]\n"
               "以下功能仅在您开启特定高级模式时才会使用：\n\n");

  print_check("FUSE 支持", "用户态文件系统 (FUSE) 挂载支持",
              access("/dev/fuse", F_OK) == 0 || grep_file("/proc/filesystems", "fuse"));
  print_check("TUN/TAP 支持", "虚拟网络设备 (TUN/TAP) 创建能力",
              access("/dev/net/tun", F_OK) == 0);
  print_check("OverlayFS 支持", "开启 --volatile 易失模式所必需的支持",
              grep_file("/proc/filesystems", "overlay"));
  print_check("Network 命名空间", "支持在 --net=none 下使用隔离的网络栈",
              check_ns(CLONE_NEWNET, "net"));

  /* 安全加固 (HARDENING) */
  check_append("\n[安全加固]\n"
               "下面这些选项并非 " PROJECT_NAME " 运行所必须，但能大幅提高沙盒隔离的安全性：\n\n");

  const bool has_user_ns = access("/proc/self/ns/user", F_OK) == 0;
  print_check("禁用 CONFIG_USER_NS",
              "当前内核启用了 User 命名空间，本程序并不需要该功能，处于安全考虑，建议将其禁用",
              !has_user_ns);

  /* 最终摘要总结 (FINAL SUMMARY) */
  check_append("\n最终诊断总结:\n\n");
  if (missing_must > 0)
    check_append("  [✗] 发现缺失了 %d 项【必须功能】 - " PROJECT_NAME " 将无法在当前系统运行\n",
                 missing_must);
  else
    check_append("  [✓] 系统满足全部必需功能，可以正常运行！\n");

  if (!is_root) {
    check_append("\n[!] 警告：您目前不是以 root 权限运行，所以有些底层检查的结果可能并不准确。\n");
  }
  check_append("\n");

  /* 一次性将缓冲区打印到终端 */
  fwrite(check_buf, 1, check_buf_pos, stdout);
  fflush(stdout);

  return 0;
}