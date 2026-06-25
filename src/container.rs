//! 容器生命周期 —— 对应原 container.c。
//!
//! 实现 start/stop/restart/info/usage 的完整流程。

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Mutex;

use crate::constants::{self, FORK_MARKER, STOP_TIMEOUT};
use crate::types::{Config, NetMode};
use crate::utils::{resolve_path_arg};
use crate::{log_error, log_info, log_warn};

// ── 跨模块引用 ──
use crate::cgroup::{cgroup_cleanup_container, print_cgroup_status};
use crate::config::{config_save, config_save_by_name};
use crate::console::console_monitor_loop;
use crate::mount::{cleanup_volatile_overlay, is_mountpoint, mount_rootfs_img, unmount_rootfs_img};
use crate::pid::{collect_active_uuids, count_running_containers, get_lock_dir, is_container_init, is_container_running, show_containers};
use crate::terminal::terminal_create;
use crate::utils::{
    firmware_path_add, firmware_path_remove, format_uptime, generate_uuid,
    get_container_uptime, read_proc_environ, sanitize_container_name,
    validate_container_name, write_all_raw,
};

// ══════════════════════════════════════════════════════════════════════════════
// 外部命令锁 —— CLI 独占所有权
//
// 这把锁只表示一件事：有一个外部 CLI 命令正在管理这个容器。
// 只有 CLI 父进程会创建/释放锁；monitor 对锁是只读的（is_external_lock_active）。
// 对应原 container.c 的 `acquire_external_lock`/`release_external_lock`/
// `is_external_lock_active`，原先这一整套在 Rust 重写时被完全遗漏，
// 导致 CLI 命令之间、以及 CLI 与 monitor 内部重启/退出清理逻辑之间
// 没有任何互斥保护。
// ══════════════════════════════════════════════════════════════════════════════

struct ExternalLockState {
    fd: RawFd,
    path: String,
}

/// 当前进程持有的锁 FD/路径（解决进程内多次申请锁的重入问题，
/// 例如 restart 流程里 stop→start 在同一个进程内连续发生）。
static ACTIVE_LOCK: Mutex<ExternalLockState> = Mutex::new(ExternalLockState { fd: -1, path: String::new() });

/// 构造锁文件路径：`<lock_dir>/<safe_name>.lock`
fn get_lock_path(name: &str) -> Option<String> {
    if !validate_container_name(name) {
        return None;
    }
    let safe_name = sanitize_container_name(name);
    Some(format!("{}/{}{}", get_lock_dir(), safe_name, constants::EXT_LOCK))
}

/// 创建外部命令锁 —— 只能由 CLI 父进程调用。
/// 使用 POSIX record lock（fcntl），进程退出/关闭 FD 时内核自动释放。
/// 返回 true 表示成功获取（或本进程已经持有，重入），false 表示被其它存活进程占用。
fn acquire_external_lock(name: &str) -> bool {
    {
        let guard = ACTIVE_LOCK.lock().unwrap();
        if guard.fd >= 0 {
            return true; // 重入：当前进程已经持有锁
        }
    }

    let lock_path = match get_lock_path(name) {
        Some(p) => p,
        None => return false,
    };
    let path_c = match CString::new(lock_path.as_str()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let fd = unsafe {
        libc::open(path_c.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC, 0o644)
    };
    if fd < 0 {
        return false;
    }

    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;

    if unsafe { libc::fcntl(fd, libc::F_SETLK, &mut fl as *mut libc::flock) } == 0 {
        // 成功：把 PID 写进去，仅用于纯文本 debug
        let pid_str = format!("{}\n", unsafe { libc::getpid() });
        unsafe {
            libc::ftruncate(fd, 0);
            let _ = write_all_raw(fd, pid_str.as_bytes());
        }
        let mut guard = ACTIVE_LOCK.lock().unwrap();
        guard.fd = fd;
        guard.path = lock_path;
        return true;
    }

    // 锁被其它进程占用：向内核查询持有者 PID 并打印
    let err = io::Error::last_os_error();
    if matches!(err.raw_os_error(), Some(libc::EACCES) | Some(libc::EAGAIN)) {
        let mut fl2: libc::flock = unsafe { std::mem::zeroed() };
        fl2.l_type = libc::F_WRLCK as _;
        fl2.l_whence = libc::SEEK_SET as _;
        if unsafe { libc::fcntl(fd, libc::F_GETLK, &mut fl2 as *mut libc::flock) } == 0
            && fl2.l_type != libc::F_UNLCK as _
        {
            log_warn!("Cannot acquire lock: held by process {}", fl2.l_pid);
        }
    }
    unsafe { libc::close(fd) };
    false
}

/// 释放外部命令锁 —— 只能由 CLI 父进程调用。
fn release_external_lock() {
    let mut guard = ACTIVE_LOCK.lock().unwrap();
    if guard.fd >= 0 {
        // 先 unlink 再 close：防止其它排队进程拿到一个即将被删除的孤儿文件的锁。
        if !guard.path.is_empty() {
            let _ = std::fs::remove_file(&guard.path);
        }
        unsafe { libc::close(guard.fd) };
        guard.fd = -1;
        guard.path.clear();
    }
}

/// 检查外部命令锁是否存在 —— 由 monitor 调用（只读）。
/// 返回 true 表示锁存在且持有者仍存活。
pub fn is_external_lock_active(name: &str) -> bool {
    let lock_path = match get_lock_path(name) {
        Some(p) => p,
        None => return false,
    };
    let path_c = match CString::new(lock_path.as_str()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false; // 文件不存在 -> 没有锁
    }

    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;

    if unsafe { libc::fcntl(fd, libc::F_GETLK, &mut fl as *mut libc::flock) } == 0
        && fl.l_type != libc::F_UNLCK as _
    {
        unsafe { libc::close(fd) };
        return true;
    }
    unsafe { libc::close(fd) };

    // 没有进程持有锁，但文件还存在 —— 宿主异常断电/kill -9 遗留的死锁文件，顺手清理。
    let _ = std::fs::remove_file(&lock_path);
    false
}

// ══════════════════════════════════════════════════════════════════════════════

pub fn is_valid_container_pid(pid: libc::pid_t) -> bool {
    let marker = format!("/proc/{}/root{}", pid, FORK_MARKER);
    Path::new(&marker).exists() && is_container_init(pid)
}

pub fn cleanup_container_resources(cfg: &mut Config, skip_unmount: bool, force_cleanup: bool) {
    if !force_cleanup { unsafe { libc::sync() }; }

    if !force_cleanup && cfg.hw_access && !cfg.img_mount_point.as_os_str().is_empty() {
        let fw_path = format!("{}/lib/firmware", cfg.img_mount_point.display());
        let _ = firmware_path_remove(Path::new(&fw_path));
    }

    if cfg.volatile_mode {
        if force_cleanup {
            let merged = format!("{}/merged", cfg.volatile_dir.display());
            let base = cfg.volatile_dir.to_string_lossy().to_string();
            unsafe {
                libc::umount2(CString::new(merged.as_str()).unwrap().as_ptr(), libc::MNT_DETACH | libc::MNT_FORCE);
                libc::umount2(CString::new(base.as_str()).unwrap().as_ptr(), libc::MNT_DETACH | libc::MNT_FORCE);
            }
            let _ = crate::utils::remove_recursive(Path::new(&cfg.volatile_dir));
            cfg.volatile_dir = Path::new("").into();
        } else {
            cleanup_volatile_overlay(cfg);
        }
    }

    let mount_point = cfg.img_mount_point.to_string_lossy().to_string();
    if !mount_point.is_empty() && !skip_unmount {
        if force_cleanup {
            let mp_c = CString::new(mount_point.as_str()).unwrap();
            unsafe { libc::umount2(mp_c.as_ptr(), libc::MNT_DETACH | libc::MNT_FORCE) };
            let _ = std::fs::remove_dir(&mount_point);
        } else {
            unmount_rootfs_img(&mount_point, cfg.foreground);
        }
    }

    let rootfs = cfg.rootfs_img_path.to_string_lossy().to_string();
    if !rootfs.is_empty() && !skip_unmount
        && is_mountpoint(Path::new(&rootfs)) {
            let r_c = CString::new(rootfs.as_str()).unwrap();
            unsafe { libc::umount2(r_c.as_ptr(), libc::MNT_DETACH) };
        }

    if !skip_unmount {
        cgroup_cleanup_container(&cfg.container_name);
    }
}

// ── Stop ──

pub fn stop_rootfs_with_timeout(cfg: &mut Config, skip_unmount: bool, timeout_seconds: i32) -> i32 {
    let timeout = if timeout_seconds < 0 { STOP_TIMEOUT } else { timeout_seconds };

    // 先抢外部命令锁——和另一个同时操作这个容器的 CLI 命令互斥，
    // 也让 monitor 在容器退出时能看到"CLI 正在管理"从而让路，不做自己的清理。
    if !acquire_external_lock(&cfg.container_name) {
        log_error!("Cannot stop '{}': another command is managing this container", cfg.container_name);
        log_error!("Wait for the other operation to complete, or use '{}' show' to check status", constants::PROJECT_NAME);
        return -1;
    }

    let pid = match is_container_running(cfg) {
        Ok(p) => p,
        Err(_) => {
            log_error!("Container '{}' is not running.", cfg.container_name);
            release_external_lock();
            return -1;
        }
    };

    log_info!("Stopping container '{}' (PID {})...", cfg.container_name, pid);

    // Read mount path from /proc if needed
    if cfg.img_mount_point.as_os_str().is_empty() {
        if let Ok(Some(mp)) = read_proc_environ(pid, "RUNTIME_MOUNT_PATH") {
            cfg.img_mount_point = mp.into();
        }
    }

    unsafe { libc::kill(pid, libc::SIGRTMIN() + 3) };
    log_info!("Waiting for graceful shutdown (up to {} seconds)...", timeout);

    let mut stopped = false;
    for _ in 0..timeout * 5 {
        if unsafe { libc::kill(pid, 0) } < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            stopped = true; break;
        }
        std::thread::sleep(std::time::Duration::from_micros(constants::RETRY_DELAY_US as u64));
    }

    let mut unkillable = false;
    if !stopped {
        log_warn!("Graceful stop timed out, sending SIGKILL...");
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut killed = false;
        for _ in 0..25 {
            if unsafe { libc::kill(pid, 0) } < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                killed = true; break;
            }
            std::thread::sleep(std::time::Duration::from_micros(200_000));
        }
        if !killed {
            unkillable = true;
            log_error!("Container PID {} is in an unkillable state!", pid);
        }
    }

    if !unkillable && !cfg.img_mount_point.as_os_str().is_empty() && cfg.hw_access {
        let fw = format!("{}/lib/firmware", cfg.img_mount_point.display());
        let _ = firmware_path_remove(Path::new(&fw));
    }

    cleanup_container_resources(cfg, skip_unmount, unkillable);

    if !cfg.foreground { log_info!("Container '{}' stopped.", cfg.container_name); }

    // 只有"终止"性的 stop 才释放锁；restart 场景下（skip_unmount=true）
    // 保留锁，把它当作交给紧接着的 start_rootfs 的"句柄交接"凭证。
    if !skip_unmount {
        release_external_lock();
    }
    0
}

pub fn stop_rootfs(cfg: &mut Config, skip_unmount: bool) -> i32 {
    stop_rootfs_with_timeout(cfg, skip_unmount, STOP_TIMEOUT)
}

// ── Start ──

pub fn start_rootfs(cfg: &mut Config) -> i32 {
    if cfg.container_name.is_empty() { log_error!("Container name required."); return -1; }

    // 0. 重启句柄交接检测：如果存在这个容器名的外部命令锁文件，说明这很可能是
    // restart 流程里紧接着 stop（skip_unmount=true）之后调用的 start——
    // 同一个进程已经持有这把锁（acquire_external_lock 的重入分支会立刻返回成功），
    // 此时应当复用 stop 阶段特意保留下来的挂载点，而不是把它当成"陈旧挂载"
    // 强制 umount 再重新走一遍 loop 设备 attach 流程。
    let mut lock_acquired = false;
    if get_lock_path(&cfg.container_name).map(|p| Path::new(&p).exists()).unwrap_or(false) {
        if acquire_external_lock(&cfg.container_name) {
            lock_acquired = true;
            let mp_valid = !cfg.img_mount_point.as_os_str().is_empty()
                && is_mountpoint(Path::new(&cfg.img_mount_point));
            if !mp_valid {
                // 锁存在但挂载点已经失效——这是一个无效的遗留锁，释放掉，
                // 走下面正常的"全新启动"流程。
                release_external_lock();
                lock_acquired = false;
            }
        }
    }

    if !lock_acquired && is_container_running(cfg).is_ok() {
        log_error!("Container name '{}' is already in use.", cfg.container_name);
        return -1;
    }

    crate::pid::ensure_runtime().ok();

    // Resolve symlinks
    if !cfg.rootfs_img_path.as_os_str().is_empty() {
        let rp = cfg.rootfs_img_path.to_string_lossy().to_string();
        if let Ok(resolved) = resolve_path_arg(&rp) {
            cfg.rootfs_img_path = resolved;
        }
    }

    if cfg.foreground && unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
        cfg.foreground = false;
        log_warn!("No interactive terminal - foreground mode disabled.");
    }

    print_cgroup_status(cfg);

    // Mount rootfs image —— 句柄交接场景下挂载点已经在用，跳过重新挂载。
    if !cfg.rootfs_img_path.as_os_str().is_empty() && !lock_acquired {
        let img = cfg.rootfs_img_path.to_string_lossy().to_string();
        // VFS lock
        if let Ok(meta) = std::fs::metadata(&img) {
            if meta.is_file() {
                let img_c = CString::new(img.as_str()).unwrap();
                unsafe { libc::mount(img_c.as_ptr(), img_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()); }
            }
        }
        let mut mp = String::new();
        if mount_rootfs_img(&img, &mut mp, &cfg.container_name).is_err() {
            if lock_acquired { release_external_lock(); }
            return -1;
        }
        cfg.img_mount_point = mp.into();
    }

    // Verify init binary
    let init_bin = if cfg.custom_init.as_os_str().is_empty() { constants::DEFAULT_INIT } else {
        &cfg.custom_init.to_string_lossy().to_string()
    };
    let init_path = format!("{}{}", cfg.img_mount_point.display(), init_bin);
    if !Path::new(&init_path).exists() {
        log_error!("Init binary not found: {}", init_path);
        if lock_acquired { release_external_lock(); }
        return -1;
    }

    // UUID generation
    let uuids = collect_active_uuids();
    let need_new = cfg.uuid.is_empty() || uuids.contains(&cfg.uuid);
    if need_new {
        if let Ok(u) = generate_uuid() { cfg.uuid = u; }
    }

    // Persist config
    if !cfg.config_file.as_os_str().is_empty() {
        let cp = cfg.config_file.to_string_lossy().to_string();
        let _ = config_save(&cp, cfg);
    }
    let _ = config_save_by_name(&cfg.container_name, cfg);

    // Firmware path (hw_access)
    if cfg.hw_access {
        let fw = format!("{}/lib/firmware", cfg.img_mount_point.display());
        let _ = firmware_path_add(Path::new(&fw));
    }

    crate::mount::fix_host_ptys().ok();

    if terminal_create(&mut cfg.console).is_err() {
        log_error!("Failed to allocate console PTY");
        if lock_acquired { release_external_lock(); }
        return -1;
    }

    // Sync pipe
    let mut sync_pipe = [-1i32, -1i32];
    if unsafe { libc::pipe(sync_pipe.as_mut_ptr()) } < 0 {
        log_error!("pipe failed: {}", io::Error::last_os_error());
        if lock_acquired { release_external_lock(); }
        return -1;
    }
    for &fd in &sync_pipe {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }

    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut cfg.start_time) };

    let monitor_pid = unsafe { libc::fork() };
    if monitor_pid < 0 {
        unsafe { libc::close(sync_pipe[0]); libc::close(sync_pipe[1]); }
        if lock_acquired { release_external_lock(); }
        return -1;
    }

    if monitor_pid == 0 {
        unsafe { libc::close(sync_pipe[0]) };
        crate::boot::monitor_run(cfg, sync_pipe[1]);
    }

    // Parent process
    unsafe { libc::close(sync_pipe[1]) };
    let mut child_pid: libc::pid_t = 0;
    if unsafe { libc::read(sync_pipe[0], &mut child_pid as *mut libc::pid_t as *mut libc::c_void, std::mem::size_of::<libc::pid_t>()) }
        != std::mem::size_of::<libc::pid_t>() as isize {
        log_error!("Monitor failed to send container PID.");
        unsafe { libc::close(sync_pipe[0]) };
        if lock_acquired { release_external_lock(); }
        return -1;
    }
    cfg.container_pid = Some(child_pid);
    unsafe { libc::close(sync_pipe[0]) };

    log_info!("Container started with PID {} (Monitor: {})", child_pid, monitor_pid);

    if cfg.foreground {
        // 前台模式：交给 console_monitor_loop 之前就可以放锁了——
        // 句柄交接的使命已经完成（容器已经在跑），接下来 CTRL+ALT+Q
        // 触发的 stop 会自己重新获取锁。
        if lock_acquired { release_external_lock(); }
        console_monitor_loop(cfg.console.master, monitor_pid, cfg)
    } else {
        // Wait for boot marker
        let marker = format!("/proc/{}/root/run/{}", child_pid, constants::PROJECT_NAME);
        let mut booted = false;
        for _ in 0..50 {
            if Path::new(&marker).exists() { booted = true; break; }
            if unsafe { libc::kill(child_pid, 0) } < 0 { break; }
            std::thread::sleep(std::time::Duration::from_micros(100_000));
        }
        if !booted {
            log_error!("Container failed to boot correctly.");
            if lock_acquired { release_external_lock(); }
            return -1;
        }

        show_info(cfg, true);
        log_info!("Container '{}' is running in background.", cfg.container_name);
        if lock_acquired { release_external_lock(); }
        0
    }
}

// ── Info / Usage ──

pub fn show_info(cfg: &Config, trust_cfg_pid: bool) -> i32 {
    if cfg.container_name.is_empty() {
        let (count, _first_name) = count_running_containers();
        if count == 0 {
            println!("Host: unknown\n\nContainer: No containers running.\n");
            return 0;
        }
        if count == 1 { /* auto-resolve in caller */ }
        else { show_containers(cfg); return 0; }
    }

    let pid = if trust_cfg_pid && cfg.container_pid.unwrap_or(0) > 0 {
        cfg.container_pid.unwrap()
    } else {
        match is_container_running(cfg) { Ok(p) => p, Err(_) => { log_error!("Container not running."); return -1; } }
    };

    if cfg.format_output {
        println!("CONTAINER_NAME={}", cfg.container_name);
        println!("CONTAINER_PID={}", pid);
        let uptime = get_container_uptime(pid);
        if uptime >= 0 { println!("CONTAINER_UPTIME_SEC={}", uptime); }
        let net = if cfg.net_mode == NetMode::None { "none" } else { "host" };
        println!("NETWORKING_MODE={}", net);
        println!("HW_ACCESS={}", if cfg.hw_access { "full" } else if cfg.gpu_mode { "GPU" } else { "none" });
        println!("VOLATILE_MODE={}", cfg.volatile_mode as u8);
        crate::utils::show_container_usage(cfg).ok();
    } else {
        println!("Container: {} (RUNNING)", cfg.container_name);
        println!("  PID: {}", pid);
        let uptime = get_container_uptime(pid);
        if uptime >= 0 { println!("  Uptime: {}", format_uptime(uptime)); }
        println!("\nFeatures:");
        let net = if cfg.net_mode == NetMode::None { "none" } else { "host" };
        println!("  Networking: {}", net);
        if cfg.hw_access { println!("  HW access: full"); }
    }
    println!();
    0
}

pub fn restart_rootfs_with_timeout(cfg: &mut Config, timeout_seconds: i32) -> i32 {
    if is_container_running(cfg).is_err() {
        log_error!("Container not running.");
        return -1;
    }
    log_info!("Restarting container {}...", cfg.container_name);
    if stop_rootfs_with_timeout(cfg, true, timeout_seconds) < 0 { return -1; }
    println!();
    start_rootfs(cfg)
}

pub fn restart_rootfs(cfg: &mut Config) -> i32 {
    restart_rootfs_with_timeout(cfg, STOP_TIMEOUT)
}
