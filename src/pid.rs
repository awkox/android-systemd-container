//! PID 发现 / UUID 扫描 / 容器列表 —— 对应原 pid.c。
//!
//! 提供容器发现和跟踪的全套功能：
//! - 运行时目录管理
//! - 基于 os-release 的容器命名
//! - 通过 /proc 扫描进行 UUID 发现
//! - 容器状态报告（人类可读和机器可解析格式）
//! - 元数据同步和孤立容器扫描

use std::io;
use std::path::Path;

use crate::constants::{self, FORK_MARKER, IMG_MOUNT_ROOT, MAX_TRACKED_ENTRIES, UUID_LEN};
use crate::types::Config;
use crate::utils::{
    build_proc_root_path, collect_pids, count_folders, mkdir_p, parse_os_release,
    read_file, reject_container_name, sanitize_container_name,
};
use crate::{log_info, log_warn};

use crate::config::{
    config_load as real_config_load, config_save as real_config_save,
    free_config_binds as real_free_config_binds,
};

/// 检查 PID 是否确实是一个有效的 ds-fork/asc 容器 init 进程。
///
/// 对应 C 的 `is_valid_container_pid()`（container.c）。
/// 两个必要条件：
///   1. `/proc/<pid>/root/run/asc` 存在（容器在 boot.rs 中写入的身份标记）；
///   2. 该 PID 确实是其 PID 命名空间的 init（is_container_init）。
/// 这里独立内联实现而不是从 container.rs 导入：虽然 Rust 同一 crate 内模块
/// 互相调用并不存在 C 头文件式的循环依赖限制（container.rs 依赖本模块，
/// 本模块再反过来依赖 container.rs 完全合法），但 pid.rs 是更底层的
/// "PID 扫描原语"模块，让它反向依赖更高层的 container.rs 会破坏分层，
/// 所以这里保留一份与 boot.rs/container.rs 完全一致的独立实现。
fn is_valid_container_pid(pid: libc::pid_t) -> bool {
    let marker = format!("/proc/{}/root{}", pid, FORK_MARKER);
    Path::new(&marker).exists() && is_container_init(pid)
}

/// 委托给 config.rs 的真实实现（`io::Result<()>` → C 风格 `i32`）。
fn config_load(path: &str, cfg: &mut Config) -> i32 {
    match real_config_load(path, cfg) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
fn config_save(path: &str, cfg: &Config) -> i32 {
    match real_config_save(path, cfg) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
fn free_config_binds(cfg: &mut Config) {
    real_free_config_binds(cfg);
}
/// 来自 mount.c 的函数
use crate::mount::{is_mountpoint, unmount_rootfs_img};

// ══════════════════════════════════════════════════════════════════════════════
// 工作区 / 路径
// ══════════════════════════════════════════════════════════════════════════════

pub fn get_lock_dir() -> String {
    format!(
        "{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_LOCK_SUBDIR
    )
}

pub fn get_logs_dir() -> String {
    format!(
        "{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_LOGS_SUBDIR
    )
}

pub fn ensure_runtime() -> io::Result<()> {
    mkdir_p(Path::new(constants::RUNTIME_DIR), 0o755)?;
    mkdir_p(Path::new(&get_lock_dir()), 0o755)?;
    mkdir_p(Path::new(&get_logs_dir()), 0o755)?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// 容器命名
// ══════════════════════════════════════════════════════════════════════════════

pub fn generate_container_name(rootfs_path: &str) -> String {
    match parse_os_release(Path::new(rootfs_path)) {
        Ok((id, version_id)) => {
            if let Some(ver) = version_id {
                format!("{}-{}", id, ver)
            } else {
                id
            }
        }
        Err(_) => "linux-container".to_string(),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// PID 发现（UUID 扫描）
// ══════════════════════════════════════════════════════════════════════════════

/// 通过 UUID 检查容器是否正在运行，返回其 init PID。
pub fn is_container_running(cfg: &Config) -> io::Result<libc::pid_t> {
    if cfg.uuid.is_empty() {
        return Err(io::Error::other("no UUID in config"));
    }
    let pid = find_container_init_pid(&cfg.uuid);
    if pid > 0 {
        Ok(pid)
    } else {
        Err(io::Error::other("container not running"))
    }
}

/// 统计运行中的容器数量，将第一个容器名存入 first_name。
pub fn count_running_containers() -> (i32, Option<String>) {
    let pids = match collect_pids() {
        Ok(p) => p,
        Err(_) => return (0, None),
    };

    let mut running: i32 = 0;
    let mut first_name: Option<String> = None;

    for pid in &pids {
        let marker_path = build_proc_root_path(*pid, Some(FORK_MARKER));
        if !Path::new(&marker_path).exists() {
            continue;
        }
        if !is_valid_container_pid(*pid) {
            continue;
        }

        let name_path = build_proc_root_path(*pid, Some(&format!("{}/name", FORK_MARKER)));
        if let Ok(cname) = read_file(Path::new(&name_path)) {
            if running == 0 {
                first_name = Some(cname.clone());
            }
            running += 1;
        }
    }

    (running, first_name)
}

/// 通过 UUID 深度扫描查找容器 init PID。
pub fn find_container_init_pid(uuid: &str) -> libc::pid_t {
    if uuid.is_empty() {
        return 0;
    }

    let marker = format!("{}/{}", FORK_MARKER, uuid);
    let pids = match collect_pids() {
        Ok(p) => p,
        Err(_) => return 0,
    };

    for pid in &pids {
        // 快速检查：FORK_MARKER 是否存在
        let marker_base = build_proc_root_path(*pid, Some(FORK_MARKER));
        if !Path::new(&marker_base).exists() {
            continue;
        }

        // 检查特定的 UUID 标记
        let uuid_path = build_proc_root_path(*pid, Some(&marker));
        if Path::new(&uuid_path).exists() && is_valid_container_pid(*pid) {
            return *pid;
        }
    }

    0
}

/// 收集所有活跃的 UUID（32 位十六进制文件名）。
pub fn collect_active_uuids() -> Vec<String> {
    let pids = match collect_pids() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut uuids: Vec<String> = Vec::new();

    for pid in &pids {
        let marker_base = build_proc_root_path(*pid, Some(FORK_MARKER));
        let dir = match std::fs::read_dir(&marker_base) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for entry in dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if fname_str.len() != UUID_LEN {
                continue;
            }
            // 验证全为十六进制字符
            if fname_str.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
                && uuids.len() < constants::MAX_CONTAINERS {
                    uuids.push(fname_str.to_string());
                }
        }
    }

    uuids
}

// ══════════════════════════════════════════════════════════════════════════════
// 状态报告
// ══════════════════════════════════════════════════════════════════════════════

/// 格式化输出运行中的容器列表。
pub fn show_containers(cfg: &Config) -> i32 {
    let container_dir = format!(
        "{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_CONFIG_SUBDIR
    );
    let total_count = count_folders(Path::new(&container_dir)).unwrap_or(0);

    #[derive(Debug)]
    struct ContainerInfo {
        name: String,
        pid: i32,
    }

    let mut containers: Vec<ContainerInfo> = Vec::with_capacity(32);
    let pids = match collect_pids() {
        Ok(p) => p,
        Err(_) => {
            println!("\n(No containers running)\n");
            return 0;
        }
    };

    let mut max_name_len = 4usize; // "NAME"

    for pid in &pids {
        let marker = build_proc_root_path(*pid, Some(FORK_MARKER));
        if !Path::new(&marker).exists() || !is_valid_container_pid(*pid) {
            continue;
        }
        let name_path = build_proc_root_path(*pid, Some(&format!("{}/name", FORK_MARKER)));
        let cname = match read_file(Path::new(&name_path)) {
            Ok(n) => n,
            Err(_) => continue,
        };

        if containers.len() > 8192 {
            return -1;
        }
        max_name_len = max_name_len.max(cname.len());
        containers.push(ContainerInfo {
            name: cname,
            pid: *pid,
        });
    }

    if containers.is_empty() {
        println!("\n(No containers running)\n");
        return 0;
    }

    if cfg.format_output {
        println!("TOTAL_CONTAINERS={}", total_count);
        println!("RUN_CONTAINERS={}", containers.len());
        for c in &containers {
            println!("CONT_{}={}", c.name, c.pid);
        }
        println!();
    } else {
        if max_name_len > 60 {
            max_name_len = 60;
        }

        println!();
        // 表格头部
        print!("┌");
        for _ in 0..max_name_len + 2 { print!("─"); }
        print!("┬");
        for _ in 0..10 { print!("─"); }
        println!("┐");
        println!("│ {:<mw$} │ {:<8} │", "NAME", "PID", mw = max_name_len);
        print!("├");
        for _ in 0..max_name_len + 2 { print!("─"); }
        print!("┼");
        for _ in 0..10 { print!("─"); }
        println!("┤");

        for c in &containers {
            // 截断名称到 max_name_len
            let display_name = if c.name.len() > max_name_len {
                &c.name[..max_name_len]
            } else {
                &c.name
            };
            println!("│ {:<mw$} │ {:<8} │", display_name, c.pid, mw = max_name_len);
        }

        print!("└");
        for _ in 0..max_name_len + 2 { print!("─"); }
        print!("┴");
        for _ in 0..10 { print!("─"); }
        println!("┘");
        println!();
    }

    0
}

/// 检查一个 PID 是否为容器 init 进程。
///
/// 方法 1（Linux 4.1+）：检查 /proc/<pid>/status 的 NSpid 字段，
///   最后一列为 "1" 表示 innermost pid namespace 的 PID 为 1。
/// 方法 2（回退，Linux 3.8+）：比较 /proc/<pid>/ns/pid 与 /proc/1/ns/pid 的 inode。
pub fn is_container_init(pid: libc::pid_t) -> bool {
    // 方法 1：检查 NSpid
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if let Some(nspid_line) = line.strip_prefix("NSpid:") {
                // 最后一列为 innermost namespace 的 PID
                let last_val = nspid_line
                    .split_whitespace()
                    .last()
                    .unwrap_or("");
                return last_val == "1";
            }
        }
    }

    // 方法 2：回退 —— 比较 ns/pid inode
    let ns_path = format!("/proc/{}/ns/pid", pid);
    let st_pid = match std::fs::metadata(&ns_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let st_host = match std::fs::metadata("/proc/1/ns/pid") {
        Ok(m) => m,
        Err(_) => return false,
    };

    use std::os::unix::fs::MetadataExt;
    st_pid.ino() != st_host.ino()
}

/// 从容器内部标记恢复宿主机端元数据（config、pid、mount）。
pub fn metadata_sync(pid: libc::pid_t) -> i32 {
    if pid <= 1 || !is_valid_container_pid(pid) {
        return -1;
    }

    // 1. 解析身份
    let name_path = build_proc_root_path(pid, Some(&format!("{}/name", FORK_MARKER)));
    let name = match read_file(Path::new(&name_path)) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    if reject_container_name(&name).is_err() {
        return -1;
    }

    let safe_name = sanitize_container_name(&name);

    // 2. 恢复工作区目录
    let container_dir = format!(
        "{}/{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_CONFIG_SUBDIR,
        safe_name
    );
    if mkdir_p(Path::new(&container_dir), 0o755).is_err() {
        return -1;
    }

    // 3. 恢复配置
    let config_path_str = build_proc_root_path(
        pid,
        Some(&format!("{}/container.config", FORK_MARKER)),
    );
    let mut recovery_cfg = Config::default();
    let config_restored = config_load(&config_path_str, &mut recovery_cfg) == 0;

    if config_restored {
        let new_path = format!("{}/container.config", container_dir);
        // recovery_cfg.config_file 在 Rust 中是 PathBuf，直接设
        recovery_cfg.config_file = new_path.clone().into();
    }

    // 4. 读取挂载路径
    if let Ok(Some(mount)) = crate::utils::read_proc_environ(pid, "RUNTIME_MOUNT_PATH") {
        recovery_cfg.img_mount_point = mount.into();
    } else {
        let mount_path =
            build_proc_root_path(pid, Some(&format!("{}/mount", FORK_MARKER)));
        if let Ok(mount) = read_file(Path::new(&mount_path)) {
            recovery_cfg.img_mount_point = mount.into();
        }
    }

    // 5. 持久化恢复的配置
    if config_restored && !recovery_cfg.config_file.as_os_str().is_empty() {
        let cfg_path = recovery_cfg.config_file.to_string_lossy().to_string();
        if config_save(&cfg_path, &recovery_cfg) < 0 {
            log_warn!("Recovery: Failed to persist configuration for PID {}", pid);
        } else {
            log_info!("Recovery: Restored missing configuration for container '{}'", safe_name);
        }
    }

    free_config_binds(&mut recovery_cfg);
    0
}

/// 完整恢复扫描：寻找未跟踪的容器和孤立的挂载。
pub fn scan_containers() -> i32 {
    log_info!("Scanning system for untracked {} containers...", constants::PROJECT_NAME);

    let pids = match collect_pids() {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // 1. 跟踪的挂载点（检测孤立挂载）
    let mut tracked_mounts: Vec<String> = Vec::with_capacity(MAX_TRACKED_ENTRIES);

    // 2. 处理所有运行中的 PID
    let mut recovered_found: i32 = 0;
    for pid in &pids {
        if *pid <= 1 {
            continue;
        }
        if is_valid_container_pid(*pid) && is_container_init(*pid)
            && metadata_sync(*pid) == 0 {
                recovered_found += 1;
            }
    }

    // 3. 获取跟踪的挂载点列表
    let cdir = format!(
        "{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_CONFIG_SUBDIR
    );
    if let Ok(cd) = std::fs::read_dir(&cdir) {
        for entry in cd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            if tracked_mounts.len() >= MAX_TRACKED_ENTRIES {
                break;
            }
            let cfg_path = format!(
                "{}/{}/container.config",
                cdir,
                entry.file_name().to_string_lossy()
            );
            let mut tmp_cfg = Config::default();
            if config_load(&cfg_path, &mut tmp_cfg) == 0 {
                let mp = tmp_cfg.img_mount_point.to_string_lossy().to_string();
                if !mp.is_empty() {
                    tracked_mounts.push(mp);
                }
                free_config_binds(&mut tmp_cfg);
            }
        }
    }

    // 4. 扫描 IMG_MOUNT_ROOT 下的孤立 loop 挂载
    let mut orphaned_found: i32 = 0;
    if let Ok(md) = std::fs::read_dir(IMG_MOUNT_ROOT) {
        for entry in md {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }

            let mpath = format!(
                "{}/{}",
                IMG_MOUNT_ROOT,
                entry.file_name().to_string_lossy()
            );

            if is_mountpoint(Path::new(&mpath)) {
                let is_tracked = tracked_mounts.iter().any(|t| t == &mpath);
                if !is_tracked {
                    log_warn!("Found orphaned mount: {}, cleaning up...", mpath);
                    unmount_rootfs_img(&mpath, false);
                    orphaned_found += 1;
                }
            } else {
                let _ = std::fs::remove_dir(&mpath);
            }
        }
    }

    if recovered_found == 0 && orphaned_found == 0 {
        log_info!("No untracked resources found.");
    } else {
        log_info!(
            "Scan complete: synchronized {} container(s), cleaned {} orphaned mount(s).",
            recovered_found,
            orphaned_found
        );
    }

    0
}
