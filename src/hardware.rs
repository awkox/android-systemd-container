//! GPU / 硬件设备镜像 —— 对应原 hardware.c。
//!
//! 管理 GPU 加速和硬件设备节点镜像。
//! 仅使用 "渲染节点"（/dev/dri/renderD*）以确保宿主机 X11/Wayland 稳定。
//!
//! `is_dangerous_node()` 包含 37+ 层危险节点阻止列表。

use std::ffi::CString;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use crate::{log_info, log_warn};

// ══════════════════════════════════════════════════════════════════════════════
// GPU 扫描路径
// ══════════════════════════════════════════════════════════════════════════════

/// 动态目录扫描路径
const GPU_SCAN_DIRS: &[(&str, Option<&str>)] = &[
    ("/dev/dri", Some("renderD")),
    ("/dev", Some("nvidia")),
    ("/dev", Some("video")),
    ("/dev/nvidia-caps", None),
    ("/dev", Some("mali")),
    ("/dev", Some("kgsl")),
    ("/dev/dma_heap", None),
];

/// 静态设备路径（独立节点）
const GPU_STATIC_DEVICES: &[&str] = &[
    "/dev/binder", "/dev/vndbinder", "/dev/hwbinder",
    "/dev/ion", "/dev/ashmem",
    "/dev/mali", "/dev/genlock",
    "/dev/kfd",
    "/dev/pvrsrvkm", "/dev/pvr_sync",
    "/dev/nvhost-ctrl", "/dev/nvhost-gpu", "/dev/nvhost-ctrl-gpu",
    "/dev/nvhost-as-gpu", "/dev/nvhost-dbg-gpu", "/dev/nvhost-prof-gpu",
    "/dev/nvhost-tsg", "/dev/nvhost-tsg-gpu", "/dev/nvhost-vic",
    "/dev/nvhost-nvdec", "/dev/nvhost-nvdec1", "/dev/nvhost-nvenc",
    "/dev/nvhost-msenc", "/dev/nvmap",
    "/dev/dxg",
    "/dev/sw_sync",
];

// ══════════════════════════════════════════════════════════════════════════════
// 危险节点阻止列表
// ══════════════════════════════════════════════════════════════════════════════

/// 检查设备节点名称是否危险（应阻止容器访问）。
pub fn is_dangerous_node(name: &str) -> bool {
    // Tier 1: DRM card + control 节点
    if name.starts_with("card") && (name.len() == 4 || name[4..].chars().next().is_none_or(|c| c.is_ascii_digit())) {
        return true;
    }
    if name.starts_with("controlD") && (name.len() == 8 || name[8..].chars().next().is_none_or(|c| c.is_ascii_digit())) {
        return true;
    }

    // Tier 2: NVIDIA 专有主节点 + 模式设置
    if name == "nvidiactl" || name == "nvidia-modeset" { return true; }
    if name.starts_with("nvidia") && name.len() > 6 && name[6..].chars().next().is_some_and(|c| c.is_ascii_digit()) { return true; }
    if name.starts_with("nvidia-cap") { return true; }

    // Tier 3-4: VGA 仲裁器 + 帧缓冲
    if name == "vga_arbiter" { return true; }
    if name.starts_with("fb") && name.len() > 2 && name[2..].chars().next().is_some_and(|c| c.is_ascii_digit()) { return true; }

    // Tier 5: 宿主机 TTY 节点
    if let Some(rest) = name.strip_prefix("tty") {
        // 安全直通
        let safe_prefixes = ["USB", "ACM", "AMA", "THS", "mxc"];
        if safe_prefixes.iter().any(|p| rest.starts_with(p)) { return false; }
        // VT 主节点危险
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) { return true; }
        // 其他未知 tty* 默认阻止
        return true;
    }

    // Tier 6: MTK 调制解调器 + BSD PTY
    if name.starts_with("ccci") || name.starts_with("umts_") { return true; }
    if name.starts_with("pty") { return true; }

    // Tier 7: 输入注入 + RF Kill
    if name == "uinput" || name == "rfkill" { return true; }

    // Tier 8: TEE / TrustZone / 安全 OS
    if name.starts_with("tz") || name.starts_with("trusty") || name.starts_with("gz_") || name.starts_with("tee") { return true; }
    if name.starts_with("conn") || name == "mtk_sec" { return true; }
    if name.len() >= 7 && name[..7].eq_ignore_ascii_case("mt_pmic") { return true; }
    if name == "tuihw" || name == "wlan" { return true; }

    // Tier 9: 旧版 RAM 盘
    if name.len() > 3 && name.starts_with("ram") && name[3..].chars().next().is_some_and(|c| c.is_ascii_digit()) { return true; }

    // Tier 10: 核心虚拟化节点
    let core_nodes = ["console", "tty", "full", "null", "zero", "random", "urandom", "ptmx", "initctl"];
    if core_nodes.contains(&name) { return true; }

    // 直接宿主机访问
    if matches!(name, "mem" | "kmem" | "port" | "kmsg") { return true; }
    // DisplayPort Aux
    if name.starts_with("drm_dp_aux") { return true; }
    // 虚拟控制台
    if name.starts_with("vcs") { return true; }
    // 看门狗
    if name.contains("watchdog") { return true; }

    // Qualcomm RPC + 安全接口
    if name.contains("qseecom") || name.contains("smcinvoke") || name.contains("adsprpc") { return true; }

    // DMA/Memory Gaps
    if name == "udmabuf" || name == "snapshot" { return true; }
    // TPM
    if name.starts_with("tpm") { return true; }
    // MTK STP
    if name.starts_with("stp") { return true; }

    // Qualcomm/Modem 连接漏洞
    if name.starts_with("rmnet_") || name.starts_with("ipa") || name.starts_with("at_usb") || name.starts_with("at_mdm")
        || name.starts_with("wwan_") || name.starts_with("btfmslim") || name.starts_with("btpower") || name.starts_with("smd")
        || name.starts_with("apr_") || name.contains("aud_") || name.contains("icnss_")
    { return true; }

    // Hypervisor 控制台
    if name.starts_with("hvc") || name.starts_with("gh_") { return true; }

    // MTK Audio IPI / SCP IPC
    if matches!(name, "audio_ipi" | "scp_audio_ipi" | "vow" | "vcp") { return true; }

    // Qualcomm SoC Tracing + DSP Debug
    if name.starts_with("coresight") || name.starts_with("remoteproc") || name.starts_with("rpmsg_")
        || matches!(name, "cvp" | "dcc_sram" | "spec_sync" | "synx_device") || name.starts_with("rdbg_")
    { return true; }

    // Android 兼容性节点
    if name.starts_with("anbox-") || name == "android_ssusbcon" { return true; }

    // eMMC RPMB
    if name.starts_with("rpmb") { return true; }
    // MTK Profiler + tracer
    if name == "mmp" || name == "met" { return true; }
    // MTK Co-Processor Firmware IPC
    if matches!(name, "mcupm" | "sspm" | "scp") { return true; }
    // MTK AED
    if name.len() >= 3 && name.starts_with("aed") && (name.len() == 3 || name[3..].chars().next().is_some_and(|c| c.is_ascii_digit())) { return true; }
    // pmsg (persistent RAM)
    if name.starts_with("pmsg") { return true; }
    // MTK Display Pipeline
    if matches!(name, "mdp_sync" | "fmt_sync" | "mtk_mdp" | "mml_pq" | "sec_display_debug") { return true; }
    // GPS co-processor
    if name == "gps_emi" || name == "gps_pwr" { return true; }
    // 安全元素 / 生物特征 / DRM 密钥
    if matches!(name, "goodix_fp" | "k250a" | "drm_wv" | "sec-nfc") { return true; }
    // MTK debug/tracing
    if matches!(name, "eara-io" | "RT_Monitor" | "stats") { return true; }
    if name.starts_with("wmt") { return true; }
    // MTK firmware logs
    if name.starts_with("fw_log_") || name == "sa_log_wifi" { return true; }
    // MTK Network Offload
    if name.starts_with("sipa_") || name == "mddp" || name == "usip" { return true; }
    // 直接总线访问
    if name.starts_with("gpiochip") || name.starts_with("i2c-") || name.starts_with("iio:device") { return true; }
    // 性能 + 时钟缩放
    if name.starts_with("cluster") || name.starts_with("gpu_freq") || name.starts_with("cpu_online_")
        || name == "memory_bandwidth" || name.contains("msm_audio_ion") || name.contains("msm_hdcp") || name.contains("msm_sps")
    { return true; }
    // Exynos Modem
    if name.starts_with("nr_") || name.starts_with("multipdp") || name.starts_with("modem_boot") || name == "radio0" { return true; }
    // Sensor Hub + DSPs
    if name.starts_with("bbd_") || name.starts_with("ssp_") || name == "ssp_sensorhub" { return true; }
    // Samsung Pay / 安全
    if name == "mst_ctrl" || name.starts_with("qbt") || name.starts_with("dek_") { return true; }
    // 吞吐量 + 延迟监控
    if name.contains("throughput") || name.contains("latency") { return true; }
    // Exynos 多媒体
    if matches!(name, "fimg2d" | "fmp" | "g2d" | "vertex10" | "self_display") { return true; }
    // Samsung 杂项
    if matches!(name, "ccic_misc" | "hqm_event") { return true; }
    // Exynos/Samsung 特定
    if name.contains("multipdp") || name.starts_with("ttyBCM") { return true; }
    if name == "s5p-smem" || name.starts_with("als_") { return true; }
    if name.contains("throughput") { return true; }

    false
}

// ══════════════════════════════════════════════════════════════════════════════
// GPU 节点镜像
// ══════════════════════════════════════════════════════════════════════════════

/// 将单个宿主机 GPU 设备路径镜像到容器 /dev。
fn mirror_gpu_node(host_path: &str, dev_path: &str) {
    if !host_path.starts_with("/dev/") { return; }

    let node_name = Path::new(host_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if is_dangerous_node(node_name) { return; }

    let host_meta = match std::fs::metadata(host_path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if !host_meta.file_type().is_char_device() { return; }

    let rel = &host_path[5..]; // 去掉 "/dev/"
    let tgt = format!("{}/{}", dev_path, rel);

    // 确保父目录存在
    if let Some(parent) = Path::new(&tgt).parent() {
        if parent.to_string_lossy() != dev_path {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    // 检查目标当前状态
    if let Ok(tgt_meta) = std::fs::symlink_metadata(&tgt) {
        if tgt_meta.file_type().is_char_device() {
            let _ = unsafe { libc::chown(
                CString::new(tgt.as_str()).unwrap().as_ptr(), 0, 0) };
            let _ = unsafe { libc::chmod(
                CString::new(tgt.as_str()).unwrap().as_ptr(), 0o666) };
            return;
        }
        if tgt_meta.is_dir() {
            if std::fs::remove_dir(&tgt).is_err() {
                log_warn!("[GPU] Cannot remove stale directory {}", tgt);
                return;
            }
        } else {
            let _ = std::fs::remove_file(&tgt);
        }
    }

    // mknod 创建字符设备节点
    let mode = libc::S_IFCHR | (host_meta.mode() & 0o666) as libc::mode_t;
    let tgt_c = CString::new(tgt.as_str()).unwrap();
    if unsafe { libc::mknod(tgt_c.as_ptr(), mode, host_meta.rdev()) } < 0 {
        log_warn!("[GPU] mknod {} failed: {}", tgt, io::Error::last_os_error());
        return;
    }

    let _ = unsafe { libc::chown(tgt_c.as_ptr(), 0, 0) };
    let _ = unsafe { libc::chmod(tgt_c.as_ptr(), 0o666) };

    log_info!("[GPU] Mirrored missing node: {}", tgt);
}

/// 遍历宿主机目录，将匹配前缀的条目镜像到容器 /dev。
fn do_mirror_gpu_dir(host_dir: &str, prefix: Option<&str>, dev_path: &str) {
    let dir = match std::fs::read_dir(host_dir) {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let fname = entry.file_name();
        if fname.to_string_lossy().starts_with('.') { continue; }
        if let Some(pfx) = prefix {
            if !fname.to_string_lossy().starts_with(pfx) { continue; }
        }
        let full = format!("{}/{}", host_dir, fname.to_string_lossy());
        mirror_gpu_node(&full, dev_path);
    }
}

/// 公共入口：将所有 GPU/硬件设备节点镜像到容器 /dev。
pub fn mirror_gpu_nodes(dev_path: &str) {
    for (dir, prefix) in GPU_SCAN_DIRS {
        do_mirror_gpu_dir(dir, *prefix, dev_path);
    }
    for &device in GPU_STATIC_DEVICES {
        mirror_gpu_node(device, dev_path);
    }
}
