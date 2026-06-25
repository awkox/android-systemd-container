//! 系统需求检查器 —— 对应原 check.c。
//!
//! 提供两种检查模式：
//! 1. `check_requirements_hw()` —— 最小预启动检查（namespace、pivot_root、内核版本）
//! 2. `check_requirements_detailed()` —— 完整诊断报告
//!
//! # 命名空间检查 (`check_ns`)
//!
//! 两阶段验证：
//! 1. 快速检查 `/proc/self/ns/<name>` 是否存在
//! 2. 功能性检查：fork + unshare 以确认命名空间功能真正可用
//!
//! 此函数同时被外部模块（main.c、boot.c）使用，因此为 pub。

use std::io::{self, Write};

use crate::constants;
use crate::utils::{get_kernel_version, grep_file};
use crate::{log_error, log_info, log_warn};

// ══════════════════════════════════════════════════════════════════════════════
// 命名空间功能检查
// ══════════════════════════════════════════════════════════════════════════════

/// 检查内核是否支持指定的命名空间类型。
///
/// # 参数
///
/// * `flag` - CLONE_* 常量（如 `CLONE_NEWNS`、`CLONE_NEWPID` 等）
/// * `name` - /proc/self/ns/ 目录下的命名空间名称
///
/// # 返回值
///
/// `true` 表示命名空间可用，`false` 表示不支持。
pub fn check_ns(flag: i32, name: &str) -> bool {
    // 阶段 1：快速检查 /proc 条目是否存在
    let path = format!("/proc/self/ns/{}", name);
    if std::fs::metadata(&path).is_err() {
        return false;
    }

    // 阶段 2：功能性检查 —— fork + unshare
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }

    if pid == 0 {
        // 子进程：尝试 unshare
        if unsafe { libc::unshare(flag) } < 0 {
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::_exit(0) };
    }

    // 父进程：等待子进程退出
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

// ══════════════════════════════════════════════════════════════════════════════
// 系统调用探测
// ══════════════════════════════════════════════════════════════════════════════

/// 探测 `pivot_root` 系统调用是否存在。
///
/// 传递空指针调用 syscall；如果返回 ENOSYS 表示系统调用不存在，
/// 返回 EFAULT 或 EINVAL 表示存在（只是参数无效）。
fn check_pivot_root() -> bool {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
        )
    };
    // 如果 errno == ENOSYS，系统调用不存在
    if ret < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
        return false;
    }
    true
}

/// 检查 `/dev/loop-control` 是否存在（loop 设备支持）。
fn check_loop() -> bool {
    std::fs::metadata("/dev/loop-control").is_ok()
}

/// 探测 SECCOMP_MODE_FILTER 支持。
///
/// `prctl(PR_GET_SECCOMP)` 在没有 seccomp 时返回 ENOSYS，
/// 在已启用 seccomp 时返回当前模式，
/// 在支持但未启用时返回 EINVAL。
fn check_seccomp() -> bool {
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if ret >= 0 {
        return true;
    }
    // 支持但未启用 seccomp filter
    io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
}

/// 检查内核版本是否满足最低要求（>= 4.9）。
fn check_kernel_version_supported() -> bool {
    match get_kernel_version() {
        Ok((major, minor)) => {
            if major < constants::MIN_KERNEL_MAJOR {
                return false;
            }
            if major == constants::MIN_KERNEL_MAJOR && minor < constants::MIN_KERNEL_MINOR {
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 输出辅助函数
// ══════════════════════════════════════════════════════════════════════════════

/// 追加格式化字符串到输出缓冲区（直接使用 Arguments 避免嵌套格式化）
fn check_append(out: &mut String, args: std::fmt::Arguments) {
    use std::fmt::Write;
    let _ = out.write_fmt(args);
}

/// 打印单个检查项的结果。
///
/// # 参数
/// * `out` - 输出缓冲区
/// * `name` - 检查项名称
/// * `desc` - 失败时的描述文字
/// * `status` - 是否通过
/// * `level` - "MUST" 或 "OPT"
/// * `is_root` - 当前是否 root
fn print_check(out: &mut String, name: &str, desc: &str, status: bool, _level: &str, is_root: bool) {
    let sym = if status { "✓" } else { "✗" };

    check_append(out, format_args!("  [{}] {}\n", sym, name));

    if !status {
        check_append(out, format_args!("      {}\n", desc));
        if (name.contains("namespace") || name.contains("Root")) && !is_root {
            check_append(out, format_args!(
                "      (Note: Namespace checks require root privileges)\n"
            ));
        }
    }
}

/// 检查并关闭基于 fd 的功能探测结果。
fn check_fd_feature(fd: i32) -> bool {
    if fd >= 0 {
        unsafe { libc::close(fd) };
        true
    } else {
        false
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 最小预启动检查
// ══════════════════════════════════════════════════════════════════════════════

/// 'start' 命令的最小检查（内部使用）。
///
/// 在容器启动前快速验证必要的系统功能。
/// 返回 `Ok(())` 表示一切就绪，`Err` 表示缺少必要条件。
pub fn check_requirements_hw(hw_access: bool) -> io::Result<()> {
    let mut missing: i32 = 0;

    // Root 检查
    let is_root = unsafe { libc::getuid() == 0 };
    if !is_root {
        log_error!("Must be run as root");
        log_info!("This tool requires root privileges for namespace and mount operations.");
        missing += 1;
    }

    // devtmpfs 仅 --hw-access 需要；无此模式时使用 tmpfs
    if hw_access && !grep_file(std::path::Path::new("/proc/filesystems"), "devtmpfs").unwrap_or(false) {
        log_warn!("Hardware access mode is active but this kernel does not support \
                   devtmpfs. GPU and hardware nodes may not be available.");
    }

    // 功能性命名空间检查
    if !check_ns(libc::CLONE_NEWNS, "mnt") {
        log_error!("Mount namespace is not supported by the kernel");
        log_info!("This is a REQUIRED feature for filesystem isolation.");
        missing += 1;
    }
    if !check_ns(libc::CLONE_NEWPID, "pid") {
        log_error!("PID namespace is not supported by the kernel");
        log_info!("This is a REQUIRED feature for process isolation.");
        missing += 1;
    }
    if !check_ns(libc::CLONE_NEWUTS, "uts") {
        log_error!("UTS namespace is not supported by the kernel");
        log_info!("This is a REQUIRED feature for hostname isolation.");
        missing += 1;
    }
    if !check_ns(libc::CLONE_NEWIPC, "ipc") {
        log_error!("IPC namespace is not supported by the kernel");
        log_info!("This is a REQUIRED feature for IPC isolation.");
        missing += 1;
    }

    if !check_pivot_root() {
        log_error!("pivot_root syscall is not supported on the current filesystem");
        log_info!("{} requires a rootfs that supports pivot_root (not ramfs).",
                  constants::PROJECT_NAME);
        missing += 1;
    }

    if !check_kernel_version_supported() {
        log_error!("Kernel version is too old");
        log_info!("{} requires at least Linux {}.{}.0.",
                  constants::PROJECT_NAME,
                  constants::MIN_KERNEL_MAJOR,
                  constants::MIN_KERNEL_MINOR);
        missing += 1;
    }

    if missing > 0 {
        println!();
        log_error!("Missing {} required feature(s) - cannot proceed", missing);
        log_info!("Please run ./{} check for a full diagnostic report.",
                  constants::PROJECT_NAME);
        return Err(io::Error::other("missing required kernel features"));
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// 详细诊断报告
// ══════════════════════════════════════════════════════════════════════════════

/// 完整的系统需求诊断报告。
///
/// 输出分为四个部分：
/// - MUST HAVE：`asc` 运行的必要条件
/// - RECOMMENDED：建议但非必需
/// - OPTIONAL：特定功能所需
/// - HARDENING：加固建议
pub fn check_requirements_detailed() -> i32 {
    let mut out = String::with_capacity(16384);
    let mut missing_must: i32 = 0;

    let is_root = unsafe { libc::getuid() == 0 };

    check_append(&mut out, format_args!(
        "\nChecking system requirements...\n\n"
    ));

    // ── MUST HAVE ──
    check_append(&mut out, format_args!(
        "[MUST HAVE]\nThese features are required for {} to work:\n\n",
        constants::PROJECT_NAME
    ));

    if !is_root {
        missing_must += 1;
    }
    print_check(
        &mut out, "Root privileges",
        "Running as root user (required for container operations)",
        is_root, "MUST", is_root,
    );

    let kver_ok = check_kernel_version_supported();
    let kver_desc = format!(
        "Linux kernel version {}.{}.0 or later",
        constants::MIN_KERNEL_MAJOR, constants::MIN_KERNEL_MINOR
    );
    if !kver_ok {
        missing_must += 1;
    }
    print_check(&mut out, "Linux version", &kver_desc, kver_ok, "MUST", is_root);

    let has_pid_ns = check_ns(libc::CLONE_NEWPID, "pid");
    if !has_pid_ns { missing_must += 1; }
    print_check(&mut out, "PID namespace", "Process ID namespace isolation", has_pid_ns, "MUST", is_root);

    let has_mnt_ns = check_ns(libc::CLONE_NEWNS, "mnt");
    if !has_mnt_ns { missing_must += 1; }
    print_check(&mut out, "Mount namespace", "Filesystem namespace isolation", has_mnt_ns, "MUST", is_root);

    let has_uts_ns = check_ns(libc::CLONE_NEWUTS, "uts");
    if !has_uts_ns { missing_must += 1; }
    print_check(&mut out, "UTS namespace", "Hostname/domainname isolation", has_uts_ns, "MUST", is_root);

    let has_ipc_ns = check_ns(libc::CLONE_NEWIPC, "ipc");
    if !has_ipc_ns { missing_must += 1; }
    print_check(&mut out, "IPC namespace", "Inter-process communication isolation", has_ipc_ns, "MUST", is_root);

    let has_pivot = check_pivot_root();
    if !has_pivot { missing_must += 1; }
    print_check(&mut out, "pivot_root syscall", "Kernel support for the pivot_root syscall", has_pivot, "MUST", is_root);

    let has_proc_fs = std::fs::metadata("/proc/self").is_ok();
    if !has_proc_fs { missing_must += 1; }
    print_check(&mut out, "/proc filesystem", "Proc filesystem mount support", has_proc_fs, "MUST", is_root);

    let has_sys_fs = std::fs::metadata("/sys/kernel").is_ok();
    if !has_sys_fs { missing_must += 1; }
    print_check(&mut out, "/sys filesystem", "Sys filesystem mount support", has_sys_fs, "MUST", is_root);

    let has_seccomp = check_seccomp();
    if !has_seccomp { missing_must += 1; }
    print_check(&mut out, "Seccomp support", "Kernel support for Seccomp (Bypass Mode)", has_seccomp, "MUST", is_root);

    // ── RECOMMENDED ──
    check_append(&mut out, format_args!(
        "\n[RECOMMENDED]\nThese features improve functionality but are not strictly required:\n\n"
    ));

    print_check(&mut out, "epoll support", "Efficient I/O event notification",
        check_fd_feature(unsafe { libc::epoll_create1(0) }), "OPT", is_root);

    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut mask) };
    print_check(&mut out, "signalfd support", "Signal handling via file descriptors",
        check_fd_feature(unsafe { libc::signalfd(-1, &mask, 0) }), "OPT", is_root);

    print_check(&mut out, "PTY support", "Unix98 PTY support",
        std::fs::metadata("/dev/ptmx").is_ok(), "OPT", is_root);

    print_check(&mut out, "devpts support", "Virtual terminal filesystem support",
        std::fs::metadata("/dev/pts").is_ok(), "OPT", is_root);

    print_check(&mut out, "Loop device", "Required for rootfs.img mounting",
        check_loop(), "OPT", is_root);

    print_check(&mut out, "ext4 filesystem", "Ext4 filesystem support",
        grep_file(std::path::Path::new("/proc/filesystems"), "ext4").unwrap_or(false), "OPT", is_root);

    print_check(&mut out, "Cgroup v2 support", "Unified Control Group hierarchy support",
        grep_file(std::path::Path::new("/proc/filesystems"), "cgroup2").unwrap_or(false), "OPT", is_root);

    print_check(&mut out, "Cgroup namespace", "Control Group namespace isolation",
        check_ns(libc::CLONE_NEWCGROUP, "cgroup"), "OPT", is_root);

    let has_devtmpfs = grep_file(std::path::Path::new("/proc/filesystems"), "devtmpfs").unwrap_or(false);
    print_check(&mut out, "devtmpfs support",
        "Required for hardware access mode; tmpfs fallback used otherwise",
        has_devtmpfs, "OPT", is_root);

    // ── OPTIONAL ──
    check_append(&mut out, format_args!(
        "\n[OPTIONAL]\nThese features are optional and only used for specific functionality:\n\n"
    ));

    let has_fuse = std::fs::metadata("/dev/fuse").is_ok()
        || grep_file(std::path::Path::new("/proc/filesystems"), "fuse").unwrap_or(false);
    print_check(&mut out, "FUSE support", "Filesystem in Userspace support", has_fuse, "OPT", is_root);

    print_check(&mut out, "TUN/TAP support", "Virtual network device support",
        std::fs::metadata("/dev/net/tun").is_ok(), "OPT", is_root);

    print_check(&mut out, "OverlayFS support", "Required for --volatile mode",
        grep_file(std::path::Path::new("/proc/filesystems"), "overlay").unwrap_or(false), "OPT", is_root);

    print_check(&mut out, "Network namespace", "Network namespace isolation for --net=none",
        check_ns(libc::CLONE_NEWNET, "net"), "OPT", is_root);

    // ── HARDENING ──
    check_append(&mut out, format_args!(
        "\n[HARDENING]\nThese checks are not required for {} to work, \
         but are recommended for hardened kernels:\n\n",
        constants::PROJECT_NAME
    ));

    let has_user_ns = std::fs::metadata("/proc/self/ns/user").is_ok();
    print_check(&mut out, "CONFIG_USER_NS disabled",
        &format!(
            "Kernel exposes user namespace support, which {} does not require and hardened kernels should disable",
            constants::PROJECT_NAME
        ),
        !has_user_ns, "OPT", is_root);

    // ── FINAL SUMMARY ──
    check_append(&mut out, format_args!(
        "\nSummary:\n\n"
    ));

    if missing_must > 0 {
        check_append(&mut out, format_args!(
            "  [✗] {} required feature(s) missing - {} will not work\n",
            missing_must, constants::PROJECT_NAME
        ));
    } else {
        check_append(&mut out, format_args!(
            "  [✓] All required features found!\n"
        ));
    }

    if !is_root {
        check_append(&mut out, format_args!(
            "\n[!] Warning: You are not root. Some checks may be inaccurate.\n"
        ));
    }
    check_append(&mut out, format_args!("\n"));

    // 一次性输出到终端
    print!("{}", out);
    let _ = io::stdout().flush();

    0
}
