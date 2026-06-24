//! Cgroup v1/v2 设置 —— 对应原 cgroup.c。
//!
//! 实现容器 cgroup 的完整生命周期：
//! 1. 探测宿主机 cgroup 层次结构（v1/v2）
//! 2. 引导挂载 cgroup2 到 /sys/fs/cgroup（Android Recovery 修复）
//! 3. 为容器设置 cgroup 隔离（v2 统一层次 或 v1 各控制器）
//! 4. 应用资源限制（memory.max, cpu.max, pids.max）
//! 5. 读取使用统计（memory.current, cpu.stat, pids.current）
//! 6. 停止时清理容器 cgroup 子树
//!
//! # 关键行为
//!
//! - `cgroup_host_bootstrap()`: Android Recovery 内核支持 cgroup2 但仅挂载在
//!   `/dev/cg2_bpf`；systemd 需要在 `/sys/fs/cgroup` 找到它。
//!   顺序：mkdir → tmpfs anchor → cgroup2
//! - `rmdir_cgroup_tree()`: 自底向上的 cgroup 子树删除，支持 cgroup.kill
//!   (5.14+) + 轮询 cgroup.events + 对旧内核的重试循环

use std::ffi::CString;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::constants;
use crate::types::Config;
use crate::utils::{
    grep_file, read_file, sanitize_container_name, write_file,
};
use crate::{log_error, log_info, log_warn};

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup v2 高速缓存
// ══════════════════════════════════════════════════════════════════════════════

/// 缓存 cgroup_v2 内核支持状态（-1 = 未检测，0 = 不支持，1 = 支持）
static HOST_SUPPORTS_V2_CACHED: Mutex<i32> = Mutex::new(-1);

// ══════════════════════════════════════════════════════════════════════════════
// 低级 mount(2) 辅助函数（等价于 mount.c 的 domount，待 mount.rs 完成后替换）
// ══════════════════════════════════════════════════════════════════════════════

/// 调用原始 mount(2) 系统调用。
///
/// 这是 mount.c 中 `domount()` 的最小替代，直到该模块被转换为 Rust。
fn domount_raw(
    src: &str,
    tgt: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let src_c = CString::new(src)?;
    let tgt_c = CString::new(tgt)?;
    let fstype_c = CString::new(fstype)?;
    let data_c = data.map(|d| CString::new(d).unwrap_or_default());
    let data_ptr = data_c
        .as_ref()
        .map(|c| c.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());

    let ret = unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            fstype_c.as_ptr(),
            flags,
            data_ptr,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup v2 探测
// ══════════════════════════════════════════════════════════════════════════════

/// 从 /proc/self/mountinfo 中扫描任何宿主机 cgroup2 挂载（如 Android 的 /dev/cg2_bpf）。
///
/// 跳过 ds-fork/asc 内部挂载以避免重启时的误报。
/// 返回找到的挂载点路径。
fn find_host_cgroup2_mount() -> Option<String> {
    let content = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(c) => c,
        Err(_) => return None,
    };

    for line in content.lines() {
        // 解析 " - " 分隔符之后的文件系统类型
        let dash_pos = match line.find(" - ") {
            Some(p) => p,
            None => continue,
        };
        let after_dash = &line[dash_pos + 3..];
        let fstype = after_dash.split_whitespace().next()?;

        if fstype != "cgroup2" {
            continue;
        }

        // 提取挂载点（字段 5，0-based 索引 4）
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() <= 4 {
            continue;
        }
        let mountpoint = fields[4];

        // 跳过 asc 内部挂载，避免误报
        if mountpoint.contains(&format!("/{}/", constants::PROJECT_NAME)) {
            continue;
        }

        return Some(mountpoint.to_string());
    }
    None
}

/// 检查宿主机是否运行 cgroup v2（存在任何 cgroup2 挂载）。
pub fn cgroup_host_is_v2() -> bool {
    find_host_cgroup2_mount().is_some()
}

/// 检查内核是否支持 cgroup v2（检查 /proc/filesystems）。
pub fn cgroup_kernel_supports_v2() -> bool {
    grep_file(Path::new("/proc/filesystems"), "cgroup2").unwrap_or(false)
}

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup v2 宿主机引导
// ══════════════════════════════════════════════════════════════════════════════

/// 如果宿主机尚未在 /sys/fs/cgroup 挂载 cgroup2，挂载它。
///
/// Android Recovery 内核支持 cgroup2 但只挂载在 /dev/cg2_bpf；
/// systemd 需要在 /sys/fs/cgroup 找到它。
/// 顺序：mkdir → tmpfs anchor → cgroup2。
pub fn cgroup_host_bootstrap(force_cgroupv1: bool) {
    if force_cgroupv1 {
        return;
    }

    // 检查是否已经完成
    let path = CString::new("/sys/fs/cgroup").unwrap();
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut sfs) } == 0 {
        // CGROUP2_SUPER_MAGIC = 0x63677270
        const CGROUP2_SUPER_MAGIC: libc::c_ulong = 0x63677270;
        if sfs.f_type as libc::c_ulong == CGROUP2_SUPER_MAGIC {
            return;
        }
    }

    // 检查 cgroup2 是否出现在 /proc/filesystems
    if !cgroup_kernel_supports_v2() {
        log_info!("[CGROUP] cgroup2 not in /proc/filesystems, skipping bootstrap.");
        return;
    }

    // 创建目录（如果不存在）
    if unsafe { libc::access(path.as_ptr(), libc::F_OK) } != 0 {
        if let Err(e) = crate::utils::mkdir_p(Path::new("/sys/fs/cgroup"), 0o755) {
            log_error!("[CGROUP] Failed to create /sys/fs/cgroup: {}", e);
            return;
        }
    }

    // tmpfs anchor：cgroup2 不能直接在 ramfs 上层叠
    // TMPFS_MAGIC = libc::TMPFS_MAGIC as libc::c_ulong
    let mut sfs2: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut sfs2) } == 0 {
        const CGROUP2_SUPER_MAGIC: libc::c_ulong = 0x63677270;
        let ftype = sfs2.f_type as libc::c_ulong;
        if ftype != libc::TMPFS_MAGIC as libc::c_ulong
            && ftype != CGROUP2_SUPER_MAGIC
        {
            if let Err(e) = domount_raw(
                "none",
                "/sys/fs/cgroup",
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                Some("mode=755,size=16M"),
            ) {
                log_error!(
                    "[CGROUP] Failed to mount tmpfs on /sys/fs/cgroup: {}",
                    e
                );
                return;
            }
            log_info!("[CGROUP] Mounted tmpfs anchor on /sys/fs/cgroup.");
        }
    }

    // 挂载 cgroup2
    if let Err(e) = domount_raw(
        "none",
        "/sys/fs/cgroup",
        "cgroup2",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    ) {
        log_error!(
            "Failed to mount cgroup2 on /sys/fs/cgroup: {}",
            e
        );
        return;
    }
    log_info!("Auto-mounted cgroup2 on /sys/fs/cgroup.");
}

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup v1 控制器合成
// ══════════════════════════════════════════════════════════════════════════════

/// 为所有已启用的子系统合成全新的 v1 cgroup 挂载。
///
/// 遍历 /proc/cgroups（内核真实视图）并挂载每个控制器。
/// 与 cgroup namespace 一起使用时，内核将每个挂载转换为容器隔离的 cgroupns root。
fn mount_v1_controllers() {
    let content = match std::fs::read_to_string("/proc/cgroups") {
        Ok(c) => c,
        Err(_) => return,
    };

    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

    // 跳过标题行
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let name = parts[0];
        // 第 4 列: enabled (1 = 已启用)
        let enabled: i32 = match parts[3].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if enabled == 0 {
            continue;
        }

        let mp = format!("sys/fs/cgroup/{}", name);
        let mp_path = Path::new(&mp);

        // 已设置或共挂载
        if mp_path.exists() {
            continue;
        }

        if let Err(_e) = std::fs::create_dir(mp_path) {
            continue;
        }

        let name_c = CString::new(name).unwrap();
        let mp_c = CString::new(mp.as_str()).unwrap();
        let fstype_c = CString::new("cgroup").unwrap();

        let ret = unsafe {
            libc::mount(
                fstype_c.as_ptr(),
                mp_c.as_ptr(),
                fstype_c.as_ptr(),
                flags,
                name_c.as_ptr() as *const libc::c_void,
            )
        };

        if ret < 0 {
            log_info!(
                "[CGROUP] v1 controller '{}' unavailable: {}",
                name,
                io::Error::last_os_error()
            );
            let _ = std::fs::remove_dir(mp_path);
        } else {
            log_info!("[CGROUP] v1 mounted: {}", name);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 容器 Cgroup 设置
// ══════════════════════════════════════════════════════════════════════════════

/// 为容器设置完整的 cgroup 文件系统。
///
/// v2 活跃时挂载全新的 cgroup2 层次（内核 namespace 处理隔离），
/// v1 路径时合成所有控制器的全新挂载。
/// 最后确保 systemd cgroup 层次存在（v1 上的命名 cgroup）。
pub fn setup_cgroups(force_cgroupv1: bool) -> io::Result<()> {
    cgroup_host_bootstrap(force_cgroupv1);

    let cgroup_base = Path::new("sys/fs/cgroup");
    if !cgroup_base.exists() {
        crate::utils::mkdir_p(cgroup_base, 0o755)?;
    }

    // 挂载 tmpfs 作为 cgroup 基础
    domount_raw(
        "none",
        "sys/fs/cgroup",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("mode=755,size=16M"),
    )?;

    let v2_active = cgroup_host_is_v2() && !force_cgroupv1;
    let mut systemd_setup_done = false;

    if v2_active {
        // 在容器的 cgroup namespace 内挂载全新的 cgroup2 层次
        let ret = unsafe {
            let fstype = CString::new("cgroup2").unwrap();
            let tgt = CString::new("sys/fs/cgroup").unwrap();
            libc::mount(
                fstype.as_ptr(),
                tgt.as_ptr(),
                fstype.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        };

        if ret == 0 {
            systemd_setup_done = true;
        } else {
            log_error!(
                "Failed to mount cgroup2: {}",
                io::Error::last_os_error()
            );
        }
    } else {
        // V1 路径：为所有控制器合成全新挂载
        mount_v1_controllers();
        systemd_setup_done = true; // 由下面的 systemd 命名 cgroup 处理
    }

    // 确保 systemd cgroup 层次存在
    if !v2_active {
        let systemd_mp = Path::new("sys/fs/cgroup/systemd");
        if !systemd_mp.exists() {
            let _ = std::fs::create_dir(systemd_mp);
            let ret = unsafe {
                let fstype = CString::new("cgroup").unwrap();
                let tgt = CString::new("sys/fs/cgroup/systemd").unwrap();
                let data = CString::new("none,name=systemd").unwrap();
                libc::mount(
                    fstype.as_ptr(),
                    tgt.as_ptr(),
                    fstype.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    data.as_ptr() as *const libc::c_void,
                )
            };
            if ret < 0 {
                log_error!(
                    "Failed to mount systemd cgroup: {}",
                    io::Error::last_os_error()
                );
                return Err(io::Error::last_os_error());
            }
        }
        systemd_setup_done = true;
    }

    if !systemd_setup_done {
        log_error!("Systemd cgroup setup failed. Systemd containers cannot boot.");
        return Err(io::Error::other("systemd cgroup setup failed"));
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup 子树清理
// ══════════════════════════════════════════════════════════════════════════════

/// 递归自底向上删除 cgroup 子树。
///
/// Cgroup 目录只能从叶子向上删除 —— 尝试删除非空 cgroup 返回 EBUSY。
/// 即使所有进程已退出，cgroup 状态由内核异步销毁。
///
/// 三种机制：
/// 1. cgroup.kill（内核 5.14+）：写 "1" 原子性地杀死子树中的所有进程
/// 2. 轮询 cgroup.events 等待 populated=0
/// 3. 重试循环：旧内核上短时等待异步清理完成
fn rmdir_cgroup_tree(path: &Path) {
    // 递归处理子目录
    if let Ok(dir) = std::fs::read_dir(path) {
        for entry in dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();

            if fname_str.starts_with('.') {
                continue;
            }

            if let Ok(ftype) = entry.file_type() {
                if ftype.is_dir() {
                    let child = path.join(fname_str.as_ref());
                    rmdir_cgroup_tree(&child);
                }
            }
        }
    }

    // 1. cgroup.kill（内核 5.14+）
    let kill_path = path.join("cgroup.kill");
    if kill_path.exists() {
        // 检查是否可写
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&kill_path) {
            let _ = f.write_all(b"1");
        }
    }

    // 2. 轮询 cgroup.events 等待 populated=0（最多 500ms = 50 × 10ms）
    let events_path = path.join("cgroup.events");
    for _ in 0..50 {
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            if content.contains("populated 0") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // 3. 带重试的 rmdir（旧内核上处理残留的 dying 后代，10 次 × 20ms = 200ms 上限）
    let path_c = CString::new(path.to_string_lossy().as_bytes()).unwrap_or_default();
    for _ in 0..10 {
        let ret = unsafe { libc::rmdir(path_c.as_ptr()) };
        if ret == 0 {
            return;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return;
        }
        if err.raw_os_error() != Some(libc::EBUSY) {
            return; // 意外错误，放弃
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// 删除容器的整个 cgroup 子树。
///
/// 移除 /sys/fs/cgroup/<controller>/asc/<container_name>/ 下创建的所有内容。
/// 安全地在每次 stop 上调用（ENOENT 静默忽略）。
pub fn cgroup_cleanup_container(container_name: &str) {
    if container_name.is_empty() {
        return;
    }

    let safe_name = sanitize_container_name(container_name);

    let cgroup_root = Path::new("/sys/fs/cgroup");
    let dir = match std::fs::read_dir(cgroup_root) {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        if fname_str.starts_with('.') {
            continue;
        }

        // 处理 unified v2 中 asc/ 在根下的情况
        let cg_path = if fname_str == "cgroup.procs" {
            format!(
                "/sys/fs/cgroup/{}/{}",
                constants::PROJECT_NAME,
                safe_name
            )
        } else {
            format!(
                "/sys/fs/cgroup/{}/{}/{}",
                fname_str,
                constants::PROJECT_NAME,
                safe_name
            )
        };

        let cg_path = Path::new(&cg_path);
        if !cg_path.exists() {
            continue;
        }

        rmdir_cgroup_tree(cg_path);

        if fname_str == "cgroup.procs" {
            break;
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Cgroup 状态报告
// ══════════════════════════════════════════════════════════════════════════════

/// 打印 cgroup 版本状态和限制兼容性警告。
pub fn print_cgroup_status(cfg: &Config) {
    let limits_set =
        cfg.memory_limit.is_some() || cfg.cpu_quota.is_some() || cfg.pids_limit.is_some();

    if cfg.force_cgroupv1 {
        log_warn!("Using legacy Cgroup V1 hierarchy (forced by --force-cgroupv1)");
        if limits_set {
            log_warn!(
                "Resource limits (--memory/--cpus/--pids-limit) require \
                 cgroup v2 and will not be applied for this container."
            );
        }
        return;
    }

    let mut cached = HOST_SUPPORTS_V2_CACHED.lock().unwrap();
    if *cached == -1 {
        *cached = if cgroup_kernel_supports_v2() { 1 } else { 0 };
    }

    if *cached == 0 {
        log_warn!("Host does not support Cgroup V2 (falling back to legacy V1)");
        if limits_set {
            log_warn!(
                "[CGROUP] Resource limits (--memory/--cpus/--pids-limit) require \
                 cgroup v2 and will not be applied on this host."
            );
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 控制器检测辅助函数
// ══════════════════════════════════════════════════════════════════════════════

/// 检查控制器名称是否出现在空格/换行分隔的控制器列表中。
fn ctrl_in_list(list: &str, name: &str) -> bool {
    let nlen = name.len();
    let mut p = list;

    loop {
        // 跳过空白
        p = p.trim_start();
        if p.is_empty() {
            break;
        }

        if p.starts_with(name) {
            // 必须是完整的单词：后面是空格、换行或 EOF
            let after = p.as_bytes().get(nlen).copied();
            if after.is_none()
                || after == Some(b' ')
                || after == Some(b'\n') {
                return true;
            }
        }

        // 移动到下一个单词
        if let Some(pos) = p.find([' ', '\n']) {
            p = &p[pos..];
        } else {
            break;
        }
    }

    false
}

/// 跨翻译单元使用的公共封装（container.c 用于构建 subtree_control）。
pub fn cg_word_in_list(list: &str, name: &str) -> bool {
    ctrl_in_list(list, name)
}

/// 在接触任何 cgroup 文件之前检查控制器的可用性。
fn ctrl_supported_v2(cg_path: &str, name: &str) -> bool {
    if cg_path.len() > libc::PATH_MAX as usize - 32 {
        return false;
    }

    let path = format!("{}/cgroup.controllers", cg_path);
    let buf = match read_file(Path::new(&path)) {
        Ok(b) => b,
        Err(_) => return false,
    };

    ctrl_in_list(&buf, name)
}

/// 解析 cgroup 整数文件，可能包含 "max"（无限制）。
///
/// 返回解析的值，或 -1 表示错误/无限制。
fn parse_cgroup_ll(buf: &str) -> i64 {
    let trimmed = buf.trim();
    if trimmed == "max" {
        return -1; // unlimited
    }
    trimmed.parse().unwrap_or(-1)
}

// ══════════════════════════════════════════════════════════════════════════════
// 资源限制应用
// ══════════════════════════════════════════════════════════════════════════════

/// 将资源限制写入容器 cgroup。
///
/// 要求 cgroup v2；v1 层次通常被宿主机 systemd 预先占用，无法可靠委派。
/// 修改 `cfg` 中的限制字段（将失败的项设为 None）。
pub fn cgroup_apply_limits(cfg: &mut Config) -> io::Result<()> {
    if cfg.memory_limit.is_none() && cfg.cpu_quota.is_none() && cfg.pids_limit.is_none() {
        return Ok(());
    }

    // 资源限制要求 cgroup v2
    if cfg.force_cgroupv1 || !cgroup_host_is_v2() {
        cfg.memory_limit = None;
        cfg.cpu_quota = None;
        cfg.pids_limit = None;
        return Ok(());
    }

    let safe_name = sanitize_container_name(&cfg.container_name);
    let cg = format!(
        "/sys/fs/cgroup/{}/{}",
        constants::PROJECT_NAME,
        safe_name
    );

    if !Path::new(&cg).exists() {
        log_warn!("[CGROUP] Container cgroup not found, limits skipped.");
        return Err(io::Error::other("container cgroup not found"));
    }

    let mut err_count = 0;

    // memory.max
    if let Some(mem) = cfg.memory_limit {
        if ctrl_supported_v2(&cg, "memory") {
            let path = format!("{}/memory.max", cg);
            let val = format!("{}", mem);
            if write_file(Path::new(&path), &val).is_err() {
                log_warn!(
                    "[CGROUP] memory.max: {}",
                    io::Error::last_os_error()
                );
                cfg.memory_limit = None;
                err_count += 1;
            }
        } else {
            log_warn!("[CGROUP] 'memory' controller not supported, limit skipped.");
            cfg.memory_limit = None;
        }
    }

    // cpu.max
    if let Some(quota) = cfg.cpu_quota {
        if ctrl_supported_v2(&cg, "cpu") {
            let period = cfg.cpu_period.unwrap_or(100_000);
            let path = format!("{}/cpu.max", cg);
            let val = format!("{} {}", quota, period);
            if write_file(Path::new(&path), &val).is_err() {
                log_warn!(
                    "[CGROUP] cpu.max: {}",
                    io::Error::last_os_error()
                );
                cfg.cpu_quota = None;
                err_count += 1;
            }
        } else {
            log_warn!("[CGROUP] 'cpu' controller not supported, limit skipped.");
            cfg.cpu_quota = None;
        }
    }

    // pids.max
    if let Some(pids) = cfg.pids_limit {
        if ctrl_supported_v2(&cg, "pids") {
            let path = format!("{}/pids.max", cg);
            let val = format!("{}", pids);
            if write_file(Path::new(&path), &val).is_err() {
                log_warn!(
                    "[CGROUP] pids.max: {}",
                    io::Error::last_os_error()
                );
                cfg.pids_limit = None;
                err_count += 1;
            }
        } else {
            log_warn!("[CGROUP] 'pids' controller not supported, limit skipped.");
            cfg.pids_limit = None;
        }
    }

    if err_count > 0 {
        Err(io::Error::other("some limits failed to apply"))
    } else {
        Ok(())
    }
}

/// 从容器 cgroup 读取使用统计。
///
/// 返回 `(memory_bytes, cpu_usage_usec, pids_current)`。
/// 未设置为 -1。
/// "max"（无限制/未设置）也报告为 -1。
pub fn cgroup_get_usage(cfg: &Config) -> io::Result<(i64, i64, i64)> {
    let safe_name = sanitize_container_name(&cfg.container_name);

    let v2 = cgroup_host_is_v2();

    let cg = format!(
        "/sys/fs/cgroup/{}/{}",
        constants::PROJECT_NAME,
        safe_name
    );

    if v2 {
        if !Path::new(&cg).exists() {
            return Err(io::Error::other("container cgroup not found"));
        }

        // memory.current
        let mem = {
            let path = format!("{}/memory.current", cg);
            match read_file(Path::new(&path)) {
                Ok(buf) => parse_cgroup_ll(&buf),
                Err(_) => -1,
            }
        };

        // cpu.stat → usage_usec
        let cpu_us = {
            let path = format!("{}/cpu.stat", cg);
            match read_file(Path::new(&path)) {
                Ok(buf) => {
                    if let Some(pos) = buf.find("usage_usec ") {
                        parse_cgroup_ll(&buf[pos + 11..])
                    } else {
                        -1
                    }
                }
                Err(_) => -1,
            }
        };

        // pids.current
        let pids = {
            let path = format!("{}/pids.current", cg);
            match read_file(Path::new(&path)) {
                Ok(buf) => parse_cgroup_ll(&buf),
                Err(_) => -1,
            }
        };

        Ok((mem, cpu_us, pids))
    } else {
        Ok((-1, -1, -1))
    }
}
