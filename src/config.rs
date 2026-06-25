//! 配置文件加载/保存 —— 对应原 config.c。
//!
//! 处理 key=value 配置文件，保留未知行（Android App 元数据），
//! 支持原子写入和冗余写入避免。

use std::io;
use std::path::Path;

use crate::constants;
use crate::types::{BindMount, Config, NetMode};
use crate::utils::{
    resolve_path_arg, sanitize_container_name, sort_bind_mounts,
    validate_bind_destination, validate_container_name,
};
use crate::{log_warn};

// ══════════════════════════════════════════════════════════════════════════════
// 解析辅助函数
// ══════════════════════════════════════════════════════════════════════════════

/// 去除前后空白字符
fn trim_whitespace(s: &str) -> &str {
    s.trim()
}

/// 严格布尔解析器：只认字面的 "1"（大小写不敏感）为真，其它一切都是假。
///
/// 对应 C 的 `parse_bool()`。注意：C 版本的函数注释写着"accepts 0/1,
/// true/false, yes/no, on/off"，但实际代码只比较了 "1" 和 "0"，其它输入
/// 一律落到末尾的 `return 0`——也就是说 "true"/"yes"/"on" 在 C 里实际上
/// 都被当作假。这里按 C 的真实行为对齐，而不是按注释里写的（未被实现的）
/// 设想行为。
fn parse_bool(val: &str) -> bool {
    val.eq_ignore_ascii_case("1")
}

/// 安全正整数解析器，返回 -1 表示任何错误
fn parse_ll_positive(val: &str) -> i64 {
    val.parse::<i64>().ok().filter(|&v| v > 0).unwrap_or(-1)
}

// ══════════════════════════════════════════════════════════════════════════════
// 特权标志解析
// ══════════════════════════════════════════════════════════════════════════════

pub fn parse_privileged(value: &str, cfg: &mut Config) {
    cfg.privileged_mask = 0;

    for token in value.split(',').map(trim_whitespace) {
        let t = token.to_lowercase();
        if t == "nomask" {
            cfg.privileged_mask |= crate::types::PRIV_NOMASK;
        } else if t == "nocaps" {
            cfg.privileged_mask |= crate::types::PRIV_NOCAPS;
        } else if t == "noseccomp" {
            cfg.privileged_mask |= crate::types::PRIV_NOSEC;
        } else if t == "shared" {
            cfg.privileged_mask |= crate::types::PRIV_SHARED;
        } else if t == "unfiltered-dev" {
            cfg.privileged_mask |= crate::types::PRIV_UNFILTERED;
        } else if t == "full" {
            cfg.privileged_mask |= crate::types::PRIV_FULL;
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Bind mount 解析
// ══════════════════════════════════════════════════════════════════════════════

fn parse_bind_mounts(value: &str, cfg: &mut Config) {
    // bind mount 格式在逗号分隔中嵌入冒号：src1:dest1[:ro],src2:dest2...
    // 需要智能解析，因为路径可能包含需要解析的内容
    for seg in value.split(',') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }

        // 寻找第一个和第二个冒号
        let parts: Vec<&str> = seg.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        let src_raw = trim_whitespace(parts[0]);
        let dest_raw = trim_whitespace(parts[1]);
        let ro = parts.get(2).is_some_and(|&s| trim_whitespace(s) == "ro");

        let src = resolve_path_arg(src_raw).unwrap_or_else(|_| src_raw.into());
        let dest = resolve_path_arg(dest_raw).unwrap_or_else(|_| dest_raw.into());

        if !validate_bind_destination(&dest.to_string_lossy()) {
            log_warn!(
                "Skipping unsafe bind destination '{}' from config.",
                dest.display()
            );
        } else {
            config_add_bind(cfg, &src.to_string_lossy(), &dest.to_string_lossy(), ro);
        }
    }
}

/// 向配置中添加一个 bind mount 条目。
/// 检查重复、按需扩容动态数组。
pub fn config_add_bind(cfg: &mut Config, src: &str, dest: &str, ro: bool) -> i32 {
    if src.is_empty() || dest.is_empty() {
        return 0;
    }
    if !validate_bind_destination(dest) {
        return -1;
    }

    // 检查重复
    for bind in &cfg.binds {
        if bind.src.to_string_lossy() == src && bind.dest.to_string_lossy() == dest {
            return 0;
        }
    }

    cfg.binds.push(BindMount {
        src: src.into(),
        dest: dest.into(),
        ro,
    });

    1
}

// ══════════════════════════════════════════════════════════════════════════════
// 内存管理（在 Rust 中由 Vec 自动处理）
// ══════════════════════════════════════════════════════════════════════════════

pub fn free_config_binds(cfg: &mut Config) {
    cfg.binds.clear();
}

pub fn free_config_unknown_lines(cfg: &mut Config) {
    cfg.unknown_lines.clear();
}

pub fn config_free(cfg: &mut Config) {
    free_config_binds(cfg);
    free_config_unknown_lines(cfg);
}

// ══════════════════════════════════════════════════════════════════════════════
// 配置加载
// ══════════════════════════════════════════════════════════════════════════════

/// 从文件加载配置。不存在时返回 Ok（可选配置）。
pub fn config_load(config_path: &str, cfg: &mut Config) -> io::Result<()> {
    let path = Path::new(config_path);
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            cfg.config_file_existed = false;
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    cfg.config_file_existed = true;
    free_config_unknown_lines(cfg);

    for line in content.lines() {
        let trimmed = trim_whitespace(line);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let key = trim_whitespace(key);
            let val = trim_whitespace(val);

            match key {
                "name" => {
                    if validate_container_name(val) {
                        cfg.container_name = val.to_string();
                    } else {
                        log_warn!("config: ignoring invalid container name '{}'", val);
                    }
                }
                "rootfs_path" => cfg.rootfs_img_path = val.into(),
                "img_mount_point" => cfg.img_mount_point = val.into(),
                "enable_hw_access" => cfg.hw_access = parse_bool(val),
                "enable_gpu_mode" => cfg.gpu_mode = parse_bool(val),
                "volatile_mode" => cfg.volatile_mode = parse_bool(val),
                "force_cgroupv1" => cfg.force_cgroupv1 = parse_bool(val),
                "block_nested_ns" => cfg.block_nested_ns = parse_bool(val),
                "memory_limit" => {
                    let v = parse_ll_positive(val);
                    if v > 0 {
                        cfg.memory_limit = Some(v);
                    } else {
                        log_warn!("config: ignoring invalid memory_limit '{}'", val);
                    }
                }
                "cpu_quota" => {
                    let v = parse_ll_positive(val);
                    if v > 0 {
                        cfg.cpu_quota = Some(v);
                    } else {
                        log_warn!("config: ignoring invalid cpu_quota '{}'", val);
                    }
                }
                "cpu_period" => {
                    let v = parse_ll_positive(val);
                    if v > 0 {
                        cfg.cpu_period = Some(v);
                    } else {
                        log_warn!("config: ignoring invalid cpu_period '{}'", val);
                    }
                }
                "pids_limit" => {
                    let v = parse_ll_positive(val);
                    if v > 0 {
                        cfg.pids_limit = Some(v);
                    } else {
                        log_warn!("config: ignoring invalid pids_limit '{}'", val);
                    }
                }
                "privileged" => parse_privileged(val, cfg),
                "custom_init" => {
                    if !val.starts_with('/') {
                        log_warn!("config: ignoring non-absolute custom_init path '{}'", val);
                    } else if val.contains(' ') {
                        log_warn!("config: ignoring custom_init path with spaces '{}'", val);
                    } else {
                        cfg.custom_init = val.into();
                    }
                }
                "bind_mounts" => parse_bind_mounts(val, cfg),
                "uuid" => cfg.uuid = val.to_string(),
                "net_mode" => match val {
                    "none" => cfg.net_mode = NetMode::None,
                    "host" => cfg.net_mode = NetMode::Host,
                    _ => {
                        log_warn!(
                            "Unknown network mode '{}' in config file. Defaulting to 'host'.",
                            val
                        );
                        cfg.net_mode = NetMode::Host;
                    }
                },
                _ => {
                    // 保留未知行原样（Android App 元数据）
                    cfg.unknown_lines.push(line.to_string());
                }
            }
        }
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// 配置序列化
// ══════════════════════════════════════════════════════════════════════════════

/// 将已知字段写入输出
fn config_serialize_known(out: &mut String, cfg: &Config) {
    use std::fmt::Write;

    let _ = writeln!(out, "# {} Container Configuration", constants::PROJECT_NAME);
    let _ = writeln!(out, "# Generated automatically - Changes may be overwritten");
    let _ = writeln!(out);

    if !cfg.container_name.is_empty() {
        let _ = writeln!(out, "name={}", cfg.container_name);
    }
    if !cfg.rootfs_img_path.as_os_str().is_empty() {
        let abs = resolve_path_arg(&cfg.rootfs_img_path.to_string_lossy())
            .unwrap_or_else(|_| cfg.rootfs_img_path.clone());
        let _ = writeln!(out, "rootfs_path={}", abs.display());
    }
    if !cfg.img_mount_point.as_os_str().is_empty() {
        let _ = writeln!(out, "img_mount_point={}", cfg.img_mount_point.display());
    }

    let _ = writeln!(out, "enable_hw_access={}", cfg.hw_access as u8);
    let _ = writeln!(out, "enable_gpu_mode={}", cfg.gpu_mode as u8);
    let _ = writeln!(out, "volatile_mode={}", cfg.volatile_mode as u8);
    let _ = writeln!(out, "force_cgroupv1={}", cfg.force_cgroupv1 as u8);
    let _ = writeln!(out, "block_nested_ns={}", cfg.block_nested_ns as u8);

    if let Some(mem) = cfg.memory_limit { let _ = writeln!(out, "memory_limit={}", mem); }
    if let Some(quota) = cfg.cpu_quota { let _ = writeln!(out, "cpu_quota={}", quota); }
    if let Some(period) = cfg.cpu_period { let _ = writeln!(out, "cpu_period={}", period); }
    if let Some(pids) = cfg.pids_limit { let _ = writeln!(out, "pids_limit={}", pids); }

    if cfg.privileged_mask > 0 {
        let _ = write!(out, "privileged=");
        if cfg.privileged_mask == crate::types::PRIV_FULL {
            let _ = write!(out, "full");
        } else {
            let mut first = true;
            for &(mask, name) in &[
                (crate::types::PRIV_NOMASK, "nomask"),
                (crate::types::PRIV_NOCAPS, "nocaps"),
                (crate::types::PRIV_NOSEC, "noseccomp"),
                (crate::types::PRIV_SHARED, "shared"),
                (crate::types::PRIV_UNFILTERED, "unfiltered-dev"),
            ] {
                if cfg.privileged_mask & mask != 0 {
                    let _ = write!(out, "{}{}", if first { "" } else { "," }, name);
                    first = false;
                }
            }
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "net_mode={}",
        if cfg.net_mode == NetMode::None { "none" } else { "host" }
    );

    if !cfg.uuid.is_empty() {
        let _ = writeln!(out, "uuid={}", cfg.uuid);
    }
    if !cfg.custom_init.as_os_str().is_empty() {
        let abs = resolve_path_arg(&cfg.custom_init.to_string_lossy())
            .unwrap_or_else(|_| cfg.custom_init.clone());
        let _ = writeln!(out, "custom_init={}", abs.display());
    }

    if !cfg.binds.is_empty() {
        let _ = write!(out, "bind_mounts=");
        for (i, bind) in cfg.binds.iter().enumerate() {
            let abs_src = resolve_path_arg(&bind.src.to_string_lossy())
                .unwrap_or_else(|_| bind.src.clone());
            let abs_dest = resolve_path_arg(&bind.dest.to_string_lossy())
                .unwrap_or_else(|_| bind.dest.clone());
            let _ = write!(
                out,
                "{}:{}{}{}",
                abs_src.display(),
                abs_dest.display(),
                if bind.ro { ":ro" } else { "" },
                if i < cfg.binds.len() - 1 { "," } else { "" }
            );
        }
        let _ = writeln!(out);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 配置保存
// ══════════════════════════════════════════════════════════════════════════════

/// 保存配置到文件。比较磁盘已有内容以避免冗余写入。
pub fn config_save(config_path: &str, cfg: &Config) -> io::Result<()> {
    let mut sorted_cfg = cfg.clone();
    sort_bind_mounts(&mut sorted_cfg);

    // 与磁盘配置比较以避免冗余写入
    let path = Path::new(config_path);
    if path.exists() {
        let mut disk_cfg = Config::default();
        if config_load(config_path, &mut disk_cfg).is_ok() {
            sort_bind_mounts(&mut disk_cfg);

            let mut cfg_serialized = String::new();
            let mut disk_serialized = String::new();
            config_serialize_known(&mut cfg_serialized, &sorted_cfg);
            config_serialize_known(&mut disk_serialized, &disk_cfg);

            if cfg_serialized == disk_serialized {
                return Ok(());
            }
        }
    }

    // 写入临时文件
    let temp_path = format!("{}.tmp", config_path);
    let mut out = String::new();
    config_serialize_known(&mut out, &sorted_cfg);

    // 追加未知行
    for line in &cfg.unknown_lines {
        out.push_str(line);
        if !line.ends_with('\n') {
            out.push('\n');
        }
    }

    std::fs::write(&temp_path, &out)?;
    std::fs::rename(&temp_path, config_path)?;

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// 路径推导
// ══════════════════════════════════════════════════════════════════════════════

/// 从 rootfs 路径推导出配置文件路径。
pub fn config_auto_path(rootfs_path: &str) -> Option<String> {
    if rootfs_path.is_empty() {
        return None;
    }

    let p = Path::new(rootfs_path);
    let dir = p.parent().unwrap_or(Path::new("/"));
    if dir == Path::new("/") {
        Some("/container.config".to_string())
    } else {
        Some(format!("{}/container.config", dir.display()))
    }
}

/// 通过容器名称加载配置。
pub fn config_load_by_name(name: &str, cfg: &mut Config) -> io::Result<()> {
    if name.is_empty() || !validate_container_name(name) {
        return Err(io::Error::other("invalid container name"));
    }

    let safe_name = sanitize_container_name(name);
    let config_path = format!(
        "{}/{}/{}/container.config",
        constants::RUNTIME_DIR,
        constants::RUNTIME_CONFIG_SUBDIR,
        safe_name
    );

    config_load(&config_path, cfg)
}

/// 通过容器名称保存配置。
pub fn config_save_by_name(name: &str, cfg: &Config) -> io::Result<()> {
    if name.is_empty() || !validate_container_name(name) {
        return Err(io::Error::other("invalid container name"));
    }

    let safe_name = sanitize_container_name(name);
    let container_dir = format!(
        "{}/{}/{}",
        constants::RUNTIME_DIR,
        constants::RUNTIME_CONFIG_SUBDIR,
        safe_name
    );
    crate::utils::mkdir_p(Path::new(&container_dir), 0o755)?;

    let config_path = format!("{}/container.config", container_dir);
    config_save(&config_path, cfg)
}
