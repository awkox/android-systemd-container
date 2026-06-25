//! 容器启动序列 —— 对应原 boot.c + monitor.c。
//!
//! 执行从 unshare mount namespace 到 exec init 的完整启动序列，
//! 包括 capability 加固、资源虚拟化、pivot_root 和 init exec。

use std::ffi::CString;
use std::io;
use std::path::Path;

use crate::constants::{self, FORK_MARKER};
use crate::types::{Config, PRIV_NOCAPS, PRIV_NOSEC, PRIV_SHARED};
use crate::utils::{open_container_log, close_container_log, read_file, write_file, sanitize_container_name};
use crate::{log_error, log_info, log_warn};

// ── Capability 常量（libc crate 未导出某些 CAP_* 值）──
const CAP_SYS_MODULE: libc::c_int = 16;
const CAP_SYS_RAWIO: libc::c_int = 17;
const CAP_SYS_PTRACE: libc::c_int = 19;
const CAP_SYS_PACCT: libc::c_int = 20;
const CAP_SYSLOG: libc::c_int = 34;
const CAP_MAC_ADMIN: libc::c_int = 33;
const CAP_MAC_OVERRIDE: libc::c_int = 32;
const CAP_WAKE_ALARM: libc::c_int = 35;
const CAP_BLOCK_SUSPEND: libc::c_int = 36;
const CAP_AUDIT_READ: libc::c_int = 37;
const CAP_DAC_READ_SEARCH: libc::c_int = 2;

// ── 跨模块引用 ──
use crate::cgroup::{setup_cgroups, cgroup_host_is_v2};
use crate::config::{config_load_by_name, config_save, config_free, free_config_binds};
use crate::mount::{apply_jail_mask, domount, is_mountpoint, setup_custom_binds, setup_dev, setup_devpts};
use crate::netlink::{nl_open, nl_close, nl_link_up};
use crate::pid::{find_container_init_pid, is_container_running};
use crate::seccomp::{seccomp_apply_minimal, android_seccomp_setup};
use crate::terminal::{terminal_set_stdfds, terminal_make_controlling};
use crate::virtualize::virtualize_init;
use crate::virtualize::{virtualize_update, get_pid_ns_inode};

// 直接复用 container.rs 里的真实实现，而不是各自维护一份相同的逻辑。
use crate::container::is_valid_container_pid;

// ══════════════════════════════════════════════════════════════════════════════
// Capability 加固
// ══════════════════════════════════════════════════════════════════════════════

pub fn apply_capability_hardening(hw_access: bool, privileged_mask: u32) {
    if privileged_mask & PRIV_NOCAPS != 0 {
        log_info!("[SEC] --privileged=nocaps: skipping capability drops.");
        return;
    }

    let universal_drops = [CAP_SYS_MODULE];
    let mut total_dropped = 0;

    for &cap in &universal_drops {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                log_warn!("[SEC] Failed to drop universal cap {}: {}", cap, e);
            }
        } else { total_dropped += 1; }
    }

    if hw_access {
        log_info!("[SEC] Hardware Mode: preserved bounding set (dropped {} universal caps).", total_dropped);
        return;
    }

    let caps_to_drop = [
        CAP_SYS_RAWIO, CAP_SYS_PTRACE, CAP_SYS_PACCT,
        CAP_SYSLOG, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE,
        CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ,
        CAP_DAC_READ_SEARCH,
    ];

    for &cap in &caps_to_drop {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                log_warn!("[SEC] Failed to drop cap {}: {}", cap, e);
            }
        } else { total_dropped += 1; }
    }

    log_info!("[SEC] Bounding set hardened (dropped {} caps).", total_dropped);
}

// ══════════════════════════════════════════════════════════════════════════════
// 容器启动序列
// ══════════════════════════════════════════════════════════════════════════════

pub fn internal_boot(cfg: &mut Config) -> i32 {
    open_container_log(cfg).ok();

    // NET_NONE: bring up loopback
    if cfg.net_mode != crate::types::NetMode::Host {
        if let Ok(mut nlctx) = nl_open() {
            let _ = nl_link_up(&mut nlctx, "lo");
            nl_close(nlctx);
            log_info!("[NET] Isolated network namespace: loopback up");
        }
    }

    if cfg.container_name.is_empty() {
        log_error!("CRITICAL: Boot aborted — container name is empty.");
        return -1;
    }

    if is_container_running(cfg).is_ok() {
        let existing_pid = find_container_init_pid(&cfg.uuid);
        if existing_pid > 0 && existing_pid != unsafe { libc::getpid() } {
            log_error!("CRITICAL: Boot aborted — name '{}' is already in use by PID {}.", cfg.container_name, existing_pid);
            return -1;
        }
    }

    // 1. Isolated mount namespace
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } < 0 {
        log_error!("Failed to unshare mount namespace: {}", io::Error::last_os_error());
        return -1;
    }

    // 2. MS_PRIVATE
    if unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } < 0 {
        log_error!("Failed to make / private: {}", io::Error::last_os_error());
        return -1;
    }

    // 3. Volatile overlay (inside mount namespace)
    if cfg.volatile_mode
        && crate::mount::setup_volatile_overlay(cfg).is_err() {
            log_error!("Failed to setup volatile overlay.");
            return -1;
        }

    // 4. Bind mount rootfs to itself
    let mp = CString::new(cfg.img_mount_point.to_string_lossy().as_bytes()).unwrap();
    if unsafe { libc::mount(mp.as_ptr(), mp.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()) } < 0 {
        log_error!("Failed to bind mount rootfs: {}", io::Error::last_os_error());
        return -1;
    }

    // 5. chdir to rootfs
    if unsafe { libc::chdir(mp.as_ptr()) } < 0 {
        log_error!("Failed to chdir to '{}': {}", cfg.img_mount_point.display(), io::Error::last_os_error());
        return -1;
    }

    // 6. Read UUID
    if cfg.uuid.is_empty() {
        if let Ok(u) = read_file(Path::new("run/.boot-uuid")) { cfg.uuid = u; }
    }
    let _ = std::fs::remove_file("run/.boot-uuid");

    // 7. Pre-create directories. `.old_root` 是 pivot_root 的硬性前提，
    // 创建失败（EEXIST 之外的任何错误）必须中止启动，否则失败会推迟到
    // 后面的 pivot_root 系统调用才暴露，错误信息会变得不直观。
    for dir in &[".old_root", "proc", "sys", "run", "tmp"] {
        if let Err(e) = std::fs::create_dir(dir) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                log_error!("Failed to create '{}': {}", dir, e);
                if *dir == ".old_root" {
                    log_error!("Failed to create critical directory .old_root");
                    return -1;
                }
            }
        }
    }

    // 8. Setup /dev
    if setup_dev(".", cfg.hw_access, cfg.gpu_mode, cfg.privileged_mask).is_err() {
        log_error!("Failed to setup /dev.");
        return -1;
    }

    if !cfg.reboot_cycle {
        if cfg.hw_access { log_info!("Setting up hardware access..."); }
        else if cfg.gpu_mode { log_info!("Setting up GPU-only access..."); }
        else { log_info!("Hardware access disabled: using isolated tmpfs..."); }
    }

    // 9. Mount proc, sys
    domount("proc", "proc", "proc", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None).ok();
    domount("sysfs", "sys", "sysfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None).ok();
    crate::utils::mkdir_p(Path::new("sys/fs/cgroup"), 0o755).ok();

    // Hardware holes or isolation
    if cfg.hw_access && cfg.foreground {
        if let Ok(d) = std::fs::read_dir("sys") {
            for e in d.flatten() {
                let n = e.file_name();
                if n.to_string_lossy().starts_with('.') { continue; }
                let sp = format!("sys/{}", n.to_string_lossy());
                if Path::new(&sp).is_dir() {
                    let sp_c = CString::new(sp.as_str()).unwrap();
                    unsafe { libc::mount(sp_c.as_ptr(), sp_c.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()); }
                }
            }
        }
    } else if !cfg.hw_access {
        let _ = std::fs::create_dir_all("sys/devices/virtual/net");
        let net_c = CString::new("sys/devices/virtual/net").unwrap();
        unsafe { libc::mount(net_c.as_ptr(), net_c.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()); }
    }

    // Remount /sys RO
    if !cfg.hw_access || cfg.foreground {
        unsafe { libc::mount(std::ptr::null(), c"sys".as_ptr(), std::ptr::null(), libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY, std::ptr::null()); }
    }

    // Setup cgroups
    if setup_cgroups(cfg.force_cgroupv1).is_err() {
        log_error!("Failed to setup container cgroups.");
        return -1;
    }

    // Mount tmpfs on /run and /tmp
    domount("tmpfs", "run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=755")).ok();
    domount("tmpfs", "tmp", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777")).ok();

    // Bind-mount console
    if !cfg.console.name.as_os_str().is_empty() {
        let cn = CString::new(cfg.console.name.to_string_lossy().as_bytes()).unwrap();
        unsafe { libc::mount(cn.as_ptr(), c"dev/console".as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()); }
    }

    // Custom bind mounts
    setup_custom_binds(cfg, ".");

    // pivot_root with MS_MOVE+chroot fallback
    let used_ms_move = crate::utils::is_ramfs(Path::new("/"));
    if used_ms_move {
        log_info!("Detected rootfs/ramfs root - using MS_MOVE+chroot fallback");
        if unsafe { libc::mount(c".".as_ptr(), c"/".as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null()) } < 0 {
            log_error!("MS_MOVE fallback failed: {}", io::Error::last_os_error());
            return -1;
        }
        if unsafe { libc::chroot(c".".as_ptr()) } < 0 {
            log_error!("chroot after MS_MOVE failed: {}", io::Error::last_os_error());
            return -1;
        }
    } else if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old_root".as_ptr()) } < 0 {
        log_error!("pivot_root failed: {}", io::Error::last_os_error());
        return -1;
    }

    unsafe { libc::chdir(c"/".as_ptr()) };

    // MS_SHARED propagation
    if cfg.privileged_mask & PRIV_SHARED != 0 {
        let ret = unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_SHARED, std::ptr::null()) };
        if ret < 0 {
            log_warn!("[SEC] Failed to apply MS_SHARED propagation: {}", io::Error::last_os_error());
        } else {
            log_info!("[SEC] Root mount propagation set to SHARED.");
        }
    }

    // devpts
    setup_devpts(cfg.hw_access).ok();
    // Jail mask
    apply_jail_mask(cfg.hw_access, cfg.privileged_mask).ok();

    // Resource virtualization
    if is_mountpoint(Path::new("/proc")) {
        virtualize_init(cfg).unwrap_or_else(|_| log_warn!("[VIRT] Initialization failed"));
    }

    // Reset hostname
    unsafe { libc::sethostname(c"(none)".as_ptr(), 6) };

    if !cfg.reboot_cycle {
        if !cfg.binds.is_empty() {
            log_info!("Setting up {} custom bind mount(s)...", cfg.binds.len());
        }
        let init_bin = if !cfg.custom_init.as_os_str().is_empty() {
            cfg.custom_init.to_string_lossy().to_string()
        } else {
            constants::DEFAULT_INIT.to_string()
        };
        log_info!("Booting '{}' (init: {})...", cfg.container_name, init_bin);
    }

    // Identity markers
    let _ = std::fs::create_dir(FORK_MARKER);
    if !cfg.uuid.is_empty() {
        let _ = write_file(Path::new(&format!("{}/{}", FORK_MARKER, cfg.uuid)), "");
    }
    let _ = config_save(&format!("{}/container.config", FORK_MARKER), cfg);
    let _ = write_file(Path::new(&format!("{}/name", FORK_MARKER)), &cfg.container_name);
    if !cfg.img_mount_point.as_os_str().is_empty() {
        let _ = write_file(Path::new(&format!("{}/mount", FORK_MARKER)), &cfg.img_mount_point.to_string_lossy());
    }
    let _ = write_file(Path::new(&format!("{}/version", FORK_MARKER)), env!("CARGO_PKG_VERSION"));

    if cfg.foreground {
        println!("\r\n(to exit from the foreground mode, press CTRL+ALT+Q)\r\n");
    }
    println!();

    // Cleanup .old_root
    if !used_ms_move {
        if unsafe { libc::umount2(c"/.old_root".as_ptr(), libc::MNT_DETACH) } < 0 {
            log_warn!("Failed to unmount .old_root: {}", io::Error::last_os_error());
        } else { let _ = std::fs::remove_dir("/.old_root"); }
    } else { let _ = std::fs::remove_dir("/.old_root"); }

    // Clear environment
    unsafe { libc::clearenv() };
    let project_name_c = CString::new(constants::PROJECT_NAME).unwrap();
    unsafe { libc::setenv(c"container".as_ptr(), project_name_c.as_ptr(), 1) };
    if !cfg.img_mount_point.as_os_str().is_empty() {
        let mp_str = cfg.img_mount_point.to_string_lossy();
        let mp_c = CString::new(mp_str.as_bytes()).unwrap();
        unsafe { libc::setenv(c"RUNTIME_MOUNT_PATH".as_ptr(), mp_c.as_ptr(), 1) };
    }

    // Security hardening
    seccomp_apply_minimal(cfg.privileged_mask).ok();
    android_seccomp_setup(cfg.block_nested_ns && (cfg.privileged_mask & PRIV_NOSEC == 0), cfg.privileged_mask).ok();
    apply_capability_hardening(cfg.hw_access, cfg.privileged_mask);

    // Redirect stdio to /dev/console
    let console_fd = unsafe { libc::open(c"/dev/console".as_ptr(), libc::O_RDWR) };
    if console_fd >= 0 {
        terminal_set_stdfds(console_fd).ok();
        terminal_make_controlling(console_fd).ok();

        // Set default window size
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(console_fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col == 0 && ws.ws_row == 0 {
            ws.ws_row = 24; ws.ws_col = 80;
            unsafe { libc::ioctl(console_fd, libc::TIOCSWINSZ, &ws) };
        }
        unsafe { libc::fchmod(console_fd, 0o620) };
        let _ = unsafe { libc::fchown(console_fd, 0, constants::DEFAULT_TTY_GID) };
        if console_fd > 2 { unsafe { libc::close(console_fd) }; }
    }

    // EXEC INIT
    let init_bin = if !cfg.custom_init.as_os_str().is_empty() {
        cfg.custom_init.to_string_lossy().to_string()
    } else {
        constants::DEFAULT_INIT.to_string()
    };

    // Tell systemd about cgroup hierarchy
    let cgroup2_magic: libc::c_ulong = 0x63677270;
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let is_unified = unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut sfs) } == 0
        && sfs.f_type as libc::c_ulong == cgroup2_magic;

    let init_c = CString::new(init_bin.as_str()).unwrap();
    let mut args: Vec<CString> = vec![init_c.clone()];

    if is_unified {
        args.push(CString::new("systemd.unified_cgroup_hierarchy=1").unwrap());
    } else {
        args.push(CString::new("systemd.unified_cgroup_hierarchy=0").unwrap());
        args.push(CString::new("systemd.legacy_systemd_cgroup_controller=1").unwrap());
    }

    let mut c_args: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    c_args.push(std::ptr::null());

    unsafe { libc::execve(init_c.as_ptr(), c_args.as_ptr(), std::ptr::null_mut()) };

    log_error!("Failed to execute {}: {}", init_bin, io::Error::last_os_error());
    close_container_log();
    -1
}

// ══════════════════════════════════════════════════════════════════════════════
// 监控进程
// ══════════════════════════════════════════════════════════════════════════════

pub fn monitor_run(cfg: &mut Config, sync_pipe_write: i32) -> ! {
    let mut sync_pipe_w = sync_pipe_write;

    if unsafe { libc::setsid() } < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        unsafe { libc::_exit(libc::EXIT_FAILURE) };
    }

    // Monitor hardening
    for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGPIPE, libc::SIGUSR1, libc::SIGUSR2] {
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
    crate::utils::oom_protect();
    unsafe { libc::prctl(libc::PR_SET_NAME, c"[ds-monitor]".as_ptr(), 0, 0, 0) };

    // Namespace flags
    let mut ns_flags = libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
    let cg_ns_ok = Path::new("/proc/self/ns/cgroup").exists() && cgroup_host_is_v2() && !cfg.force_cgroupv1;

    if cg_ns_ok {
        // Cgroup delegation setup
        if Path::new("/sys/fs/cgroup/cgroup.procs").exists() {
            let safe_name = sanitize_container_name(&cfg.container_name);
            let limits_set = cfg.memory_limit.is_some() || cfg.cpu_quota.is_some() || cfg.pids_limit.is_some();

            if limits_set {
                // Enable controllers in subtree_control
                let mut enable = String::new();
                if let Ok(buf) = read_file(Path::new("/sys/fs/cgroup/cgroup.controllers")) {
                    // 用 cg_word_in_list 按单词边界匹配，而不是裸子串 contains()——
                    // 否则只有 "cpuset" 没有独立 "cpu" 控制器的宿主机会被误判为
                    // "cpu" 可用（"cpuset" 这个词本身就包含 "cpu" 子串）。
                    if cfg.memory_limit.is_some() && crate::cgroup::cg_word_in_list(&buf, "memory") {
                        enable.push_str(if enable.is_empty() { "+memory" } else { " +memory" });
                    }
                    if cfg.cpu_quota.is_some() && crate::cgroup::cg_word_in_list(&buf, "cpu") {
                        enable.push_str(if enable.is_empty() { "+cpu" } else { " +cpu" });
                    }
                    if cfg.pids_limit.is_some() && crate::cgroup::cg_word_in_list(&buf, "pids") {
                        enable.push_str(if enable.is_empty() { "+pids" } else { " +pids" });
                    }
                }
                if !enable.is_empty() {
                    let _ = write_file(Path::new("/sys/fs/cgroup/cgroup.subtree_control"), &enable);
                    let _ = crate::utils::mkdir_p(Path::new(&format!("/sys/fs/cgroup/{}", constants::PROJECT_NAME)), 0o755);
                    let _ = write_file(Path::new(&format!("/sys/fs/cgroup/{}/cgroup.subtree_control", constants::PROJECT_NAME)), &enable);
                }
            }

            let cg_path = format!("/sys/fs/cgroup/{}/{}", constants::PROJECT_NAME, safe_name);
            let _ = crate::utils::mkdir_p(Path::new(&cg_path), 0o755);
            let _ = write_file(Path::new(&format!("{}/cgroup.procs", cg_path)), &unsafe { libc::getpid() }.to_string());
        }
        ns_flags |= libc::CLONE_NEWCGROUP;
    }

    // Apply resource limits
    let mut limit_cfg = cfg.clone();
    if crate::cgroup::cgroup_apply_limits(&mut limit_cfg).is_err()
        && (cfg.memory_limit.is_some() || cfg.cpu_quota.is_some() || cfg.pids_limit.is_some()) {
            log_warn!("[CGROUP] Some resource limits could not be enforced.");
        }

    if unsafe { libc::unshare(ns_flags) } < 0 {
        log_error!("unshare failed: {}", io::Error::last_os_error());
        unsafe { libc::_exit(libc::EXIT_FAILURE) };
    }

    let mut stdio_redirected = false;

    // Reboot loop
    loop {
        // First boot only: kill stale container
        if !cfg.reboot_cycle {
            let existing_pid = find_container_init_pid(&cfg.uuid);
            if existing_pid > 0 && existing_pid != unsafe { libc::getpid() } && is_valid_container_pid(existing_pid) {
                log_warn!("Killing stale container with same name (PID {})", existing_pid);
                unsafe { libc::kill(existing_pid, libc::SIGKILL) };
                std::thread::sleep(std::time::Duration::from_micros(100_000));
            }
        }

        // Background mode: redirect stdin
        if !cfg.foreground && !stdio_redirected {
            let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            if devnull >= 0 {
                unsafe { libc::dup2(devnull, 0) };
                unsafe { libc::close(devnull) };
            }
        }

        let mid_pid = unsafe { libc::fork() };
        if mid_pid < 0 { unsafe { libc::_exit(libc::EXIT_FAILURE) }; }

        if mid_pid == 0 {
            // INTERMEDIATE PROCESS
            let mut clone_flags = libc::CLONE_NEWPID;
            if cfg.net_mode != crate::types::NetMode::Host { clone_flags |= libc::CLONE_NEWNET; }

            if unsafe { libc::unshare(clone_flags) } < 0 {
                unsafe { libc::_exit(libc::EXIT_FAILURE) };
            }

            let init_pid = unsafe { libc::fork() };
            if init_pid < 0 { unsafe { libc::_exit(libc::EXIT_FAILURE) }; }

            if init_pid == 0 {
                // CONTAINER INIT (PID 1)
                unsafe { libc::close(sync_pipe_w) };
                let rc = internal_boot(cfg);
                unsafe { libc::_exit(rc) };
            }

            // Intermediate: redirect stdio
            if !cfg.foreground {
                let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
                if devnull >= 0 {
                    unsafe { libc::dup2(devnull, 0); libc::dup2(devnull, 1); libc::dup2(devnull, 2); libc::close(devnull); }
                }
            }

            // Send init PID to parent
            if sync_pipe_w >= 0 {
                unsafe { libc::write(sync_pipe_w, &init_pid as *const libc::pid_t as *const libc::c_void, std::mem::size_of::<libc::pid_t>()) };
                unsafe { libc::close(sync_pipe_w) };
            }

            // Wait for init
            let mut init_status = 0;
            while unsafe { libc::waitpid(init_pid, &mut init_status, 0) } < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {}

            if libc::WIFSIGNALED(init_status) && libc::WTERMSIG(init_status) == libc::SIGHUP {
                unsafe { libc::_exit(constants::REBOOT_EXIT) };
            }
            unsafe { libc::_exit(if libc::WIFEXITED(init_status) { libc::WEXITSTATUS(init_status) } else { libc::EXIT_FAILURE }) };
        }

        // MONITOR continues here
        if sync_pipe_w >= 0 { unsafe { libc::close(sync_pipe_w) }; sync_pipe_w = -1; }

        cfg.ns_inode = get_pid_ns_inode(cfg.container_pid.unwrap_or(0));
        unsafe { libc::chdir(c"/".as_ptr()) };

        if !cfg.foreground && !stdio_redirected {
            let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            if devnull >= 0 {
                unsafe { libc::dup2(devnull, 0); libc::dup2(devnull, 1); libc::dup2(devnull, 2); libc::close(devnull); }
            }
            stdio_redirected = true;
        }

        if sync_pipe_w >= 0 { unsafe { libc::close(sync_pipe_w) }; sync_pipe_w = -1; }

        // Heartbeat loop
        let mut status = 0;
        {
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sigaddset(&mut mask, libc::SIGCHLD) };
            let sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };

            loop {
                let r = unsafe { libc::waitpid(mid_pid, &mut status, libc::WNOHANG) };
                if r == mid_pid { break; }
                if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) { break; }

                // HOST mode: resolve container_pid
                if cfg.container_pid.unwrap_or(0) <= 0 && !cfg.uuid.is_empty() {
                    let p = find_container_init_pid(&cfg.uuid);
                    if p > 0 {
                        cfg.container_pid = Some(p);
                        cfg.ns_inode = get_pid_ns_inode(p);
                    }
                }

                virtualize_update(cfg);

                if sfd >= 0 {
                    let mut pfd = libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 };
                    unsafe { libc::poll(&mut pfd, 1, 500) };
                    if pfd.revents & libc::POLLIN != 0 {
                        let mut si: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                        while unsafe { libc::read(sfd, &mut si as *mut _ as *mut libc::c_void, std::mem::size_of::<libc::signalfd_siginfo>()) }
                            == std::mem::size_of::<libc::signalfd_siginfo>() as isize {}
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_micros(500_000));
                }
            }
            if sfd >= 0 { unsafe { libc::close(sfd) }; }
        }

        // Reboot detection。注意：reboot 分支和"正常退出"分支都要先检查
        // 外部命令锁——如果 CLI 正在用 stop/restart 管理这个容器，monitor
        // 必须让路，不做自己的清理，否则会和 CLI 的清理逻辑产生竞态
        // （双重 unmount / 双重 cgroup rmdir）。这对应原 monitor.c 里
        // `monitor_cleanup_and_exit` 标签汇聚的两条路径。
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == constants::REBOOT_EXIT {
            // 外部命令锁检测：如果 CLI 正在管理这个容器（例如用户手动执行了
            // stop/restart），让 monitor 直接让路，把清理工作交给 CLI 自己去做，
            // 避免两边同时对同一个挂载点/cgroup 做清理产生竞态。
            if crate::container::is_external_lock_active(&cfg.container_name) {
                config_free(cfg);
                let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 0 };
                unsafe { libc::_exit(code) };
            }

            if cfg.foreground {
                println!("\nasc {} : Container {} is now Rebooting\n",
                    env!("CARGO_PKG_VERSION"), cfg.container_name);
            }

            if !cfg.uuid.is_empty() {
                let new_pid = find_container_init_pid(&cfg.uuid);
                if new_pid > 0 { cfg.container_pid = Some(new_pid); }
            }

            // Write UUID to container /run
            if !cfg.volatile_mode && cfg.container_pid.unwrap_or(0) > 0 {
                let run_dir = format!("/proc/{}/root/run", cfg.container_pid.unwrap());
                let _ = std::fs::create_dir_all(&run_dir);
                let fd = crate::utils::safe_openat_proc(cfg.container_pid.unwrap(), "run/.boot-uuid", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
                if let Ok(fd) = fd {
                    let _ = unsafe { crate::utils::write_all_raw(fd, cfg.uuid.as_bytes()) };
                    unsafe { libc::close(fd) };
                }
            }

            // Reload config
            {
                free_config_binds(cfg);
                let old_force = cfg.force_cgroupv1;
                let mut reboot_cfg = cfg.clone();
                if config_load_by_name(&cfg.container_name, &mut reboot_cfg).is_ok() {
                    if reboot_cfg.force_cgroupv1 != old_force {
                        println!("force_cgroupv1 changed but requires a full stop/start\n");
                        reboot_cfg.force_cgroupv1 = old_force;
                    }
                    *cfg = reboot_cfg;
                }
            }

            cfg.reboot_cycle = true;
            unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut cfg.start_time) };
            cfg.ns_inode = get_pid_ns_inode(cfg.container_pid.unwrap_or(0));
            continue; // reboot loop
        }

        // Normal exit - cleanup
        // 同样先检查外部命令锁：如果 CLI 正在处理这个容器的 stop，
        // 让路给 CLI，不重复做 cleanup_container_resources。
        if crate::container::is_external_lock_active(&cfg.container_name) {
            config_free(cfg);
            let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 0 };
            unsafe { libc::_exit(code) };
        }

        // Move monitor to root cgroup
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/sys/fs/cgroup/cgroup.procs") {
            use std::io::Write;
            let _ = write!(f, "{}", unsafe { libc::getpid() });
        }

        // Cleanup: calls that need external modules (deferred)
        if cfg.volatile_mode {
            crate::mount::cleanup_volatile_overlay(cfg);
        }
        if !cfg.img_mount_point.as_os_str().is_empty() {
            crate::mount::unmount_rootfs_img(&cfg.img_mount_point.to_string_lossy(), cfg.foreground);
        }
        crate::cgroup::cgroup_cleanup_container(&cfg.container_name);

        config_free(cfg);
        let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 0 };
        unsafe { libc::_exit(code) };
    }
}
