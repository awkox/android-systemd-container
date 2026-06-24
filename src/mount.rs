//! 挂载操作 —— 对应原 mount.c。
//!
//! 完整容器文件系统隔离栈：挂载点管理、jail masks、/dev 设置、
//! devpts、OverlayFS、bind mount、rootfs 镜像挂载（loop 设备）。

use std::ffi::CString;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::constants;
use crate::hardware::{is_dangerous_node, mirror_gpu_nodes};
use crate::types::{Config, PRIV_NOMASK, PRIV_UNFILTERED};
use crate::utils::{
    get_runtime_dir, grep_file, is_subpath, mkdir_p, path_has_symlink,
    remove_recursive, sanitize_container_name, sort_bind_mounts, write_file,
};
use crate::{log_error, log_info, log_warn};

// ── Loop 设备 ioctl 常量（来自 <linux/loop.h>，libc crate 未导出）──

const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LO_FLAGS_AUTOCLEAR: u32 = 4;

#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

// ══════════════════════════════════════════════════════════════════════════════
// 辅助函数
// ══════════════════════════════════════════════════════════════════════════════

/// 通过比较 st_dev 判断路径是否为挂载点。
pub fn is_mountpoint(path: &Path) -> bool {
    let st1 = match path.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let parent = path.parent().unwrap_or(Path::new("/"));
    let st2 = match parent.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    st1.dev() != st2.dev()
}

fn force_unlink(path: &Path) -> io::Result<()> {
    if std::fs::remove_file(path).is_ok() {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EISDIR) => std::fs::remove_dir(path),
        Some(libc::ENOENT) => Ok(()),
        _ => Err(err),
    }
}

fn find_available_mountpoint(name: &str) -> io::Result<String> {
    let base_dir = constants::IMG_MOUNT_ROOT;
    std::fs::create_dir_all(base_dir).ok();
    let safe_name = sanitize_container_name(name);
    let mount_path = format!("{}/{}", base_dir, safe_name);

    if Path::new(&mount_path).exists() {
        if is_mountpoint(Path::new(&mount_path)) {
            log_warn!("Found stale mount at {}, cleaning up...", mount_path);
            let mount_c = CString::new(mount_path.as_str()).unwrap();
            if unsafe { libc::umount2(mount_c.as_ptr(), libc::MNT_DETACH) } < 0 {
                let stale_dev = get_backing_dev(&mount_path).unwrap_or_default();
                unsafe {
                    libc::umount2(mount_c.as_ptr(), libc::MNT_DETACH | libc::MNT_FORCE);
                }
                if !stale_dev.is_empty() {
                    loop_detach(&stale_dev);
                }
            }
        }
        return Ok(mount_path);
    }
    std::fs::create_dir(&mount_path)?;
    Ok(mount_path)
}

// ══════════════════════════════════════════════════════════════════════════════
// 通用 mount 包装
// ══════════════════════════════════════════════════════════════════════════════

pub fn domount(
    src: &str,
    tgt: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let src_c = CString::new(src).unwrap_or_default();
    let tgt_c = CString::new(tgt).unwrap();
    let fstype_c = CString::new(fstype).unwrap();
    let data_c = data.map(|d| CString::new(d).unwrap_or_default());
    let data_ptr = data_c
        .as_ref()
        .map(|c| c.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());

    let ret = unsafe {
        libc::mount(src_c.as_ptr(), tgt_c.as_ptr(), fstype_c.as_ptr(), flags, data_ptr)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBUSY) {
            log_error!("Failed to mount {} on {} ({}): {}", src, tgt, fstype, err);
        }
        Err(err)
    } else {
        Ok(())
    }
}

fn mask_path(path: &str) {
    let path_c = CString::new(path).unwrap();
    if unsafe { libc::access(path_c.as_ptr(), libc::F_OK) } != 0 {
        return;
    }
    unsafe {
        libc::mount(path_c.as_ptr(), path_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null());
        libc::mount(
            path_c.as_ptr(), path_c.as_ptr(), std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY, std::ptr::null(),
        );
    }
}

fn nullify_path(path: &str) {
    let path_c = CString::new(path).unwrap();
    if unsafe { libc::access(path_c.as_ptr(), libc::F_OK) } != 0 { return; }
    if unsafe { libc::access(c"/dev/null".as_ptr(), libc::F_OK) } != 0 { return; }
    unsafe {
        libc::mount(
            c"/dev/null".as_ptr(),
            path_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null(),
        );
    }
}

fn block_read_path(path: &str) {
    let path_c = CString::new(path).unwrap();
    if unsafe { libc::access(path_c.as_ptr(), libc::F_OK) } != 0 { return; }

    let fifo_path = format!("/tmp/.{}-kmsg-fifo-{}", constants::PROJECT_NAME, unsafe { libc::getpid() });
    let fifo_c = CString::new(fifo_path.as_str()).unwrap();
    unsafe { libc::unlink(fifo_c.as_ptr()) };
    if unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) } < 0 { return; }

    let child = unsafe { libc::fork() };
    if child == 0 {
        let wfd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY) };
        if wfd >= 0 { unsafe { libc::pause() }; }
        unsafe { libc::_exit(0) };
    }
    if child > 0 {
        unsafe {
            libc::mount(fifo_c.as_ptr(), path_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null());
        }
    }
    unsafe { libc::unlink(fifo_c.as_ptr()) };
}

// ══════════════════════════════════════════════════════════════════════════════
// 安全 bind mount
// ══════════════════════════════════════════════════════════════════════════════

pub fn bind_mount(src: &str, tgt: &str) -> io::Result<()> {
    let src_c = CString::new(src).unwrap();
    let src_fd = unsafe {
        libc::open(src_c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if src_fd < 0 { return Err(io::Error::last_os_error()); }

    let mut st_src: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_fd, &mut st_src) } < 0 {
        unsafe { libc::close(src_fd) };
        return Err(io::Error::last_os_error());
    }
    if (st_src.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        unsafe { libc::close(src_fd) };
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }

    let tgt_c = CString::new(tgt).unwrap();
    let mut st_tgt: libc::stat = unsafe { std::mem::zeroed() };
    let tgt_path = Path::new(tgt);
    if unsafe { libc::lstat(tgt_c.as_ptr(), &mut st_tgt) } < 0 {
        if path_has_symlink(tgt_path) {
            log_error!("Security Violation: symlink in bind target path {}", tgt);
            unsafe { libc::close(src_fd) };
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        if (st_src.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let _ = std::fs::create_dir(tgt_path);
        } else {
            let _ = write_file(tgt_path, "");
        }
    } else if (st_tgt.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        log_error!("Security Violation: Bind target {} is a symlink!", tgt);
        unsafe { libc::close(src_fd) };
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }

    let proc_path = format!("/proc/self/fd/{}", src_fd);
    let res = domount(&proc_path, tgt, "none", libc::MS_BIND | libc::MS_REC, None);
    unsafe { libc::close(src_fd) };
    res
}

// ══════════════════════════════════════════════════════════════════════════════
// Jail mask
// ══════════════════════════════════════════════════════════════════════════════

pub fn apply_jail_mask(hw_access: bool, privileged_mask: u32) -> io::Result<()> {
    if privileged_mask & PRIV_NOMASK != 0 {
        log_info!("[SEC] --privileged=nomask: skipping jail masks for /proc and /sys.");
        return Ok(());
    }

    let universal_masks = ["/proc/sysrq-trigger", "/proc/kcore", "/proc/timer_list"];
    let universal_nullify = ["/proc/partitions"];
    let kmsg_block_paths = ["/dev/kmsg", "/proc/kmsg"];
    let standard_ro = [
        "/proc/irq", "/sys/firmware", "/sys/kernel/security",
        "/sys/kernel/debug", "/sys/kernel/tracing", "/sys/block",
    ];

    for path in &universal_masks { mask_path(path); }
    for path in &universal_nullify { nullify_path(path); }
    for path in &kmsg_block_paths { block_read_path(path); }

    // CVE-2022-0492: mask cgroup v1 release_agent
    if let Ok(cgdir) = std::fs::read_dir("/sys/fs/cgroup") {
        for e in cgdir.flatten() {
            let fname = e.file_name();
            if fname.to_string_lossy().starts_with('.') { continue; }
            let ap = format!("/sys/fs/cgroup/{}/release_agent", fname.to_string_lossy());
            mask_path(&ap);
        }
    }

    // /proc/sys 整体 RO + hostname/domainname RW 洞
    if Path::new("/proc/sys").exists() {
        let sys_c = CString::new("/proc/sys").unwrap();
        unsafe {
            libc::mount(sys_c.as_ptr(), sys_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null());
            libc::mount(sys_c.as_ptr(), sys_c.as_ptr(), std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY, std::ptr::null());
        }
        log_info!("[SEC] /proc/sys locked RO.");

        for hole in &["/proc/sys/kernel/hostname", "/proc/sys/kernel/domainname"] {
            if !Path::new(hole).exists() { continue; }
            let hole_c = CString::new(*hole).unwrap();
            unsafe {
                if libc::mount(hole_c.as_ptr(), hole_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) < 0 {
                    log_warn!("[SEC] Failed to bind RW hole {}: {}", hole, io::Error::last_os_error());
                    continue;
                }
                if libc::mount(hole_c.as_ptr(), hole_c.as_ptr(), std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, std::ptr::null()) < 0 {
                    log_warn!("[SEC] Failed to remount RW hole {}: {}", hole, io::Error::last_os_error());
                }
            }
        }
        log_info!("[SEC] /proc/sys RW holes preserved (hostname/domainname).");
    }

    if hw_access {
        log_info!("[SEC] Hardware Mode: preserved sensitive /proc and /sys paths.");
        return Ok(());
    }
    for path in &standard_ro { mask_path(path); }
    log_info!("[SEC] Jail mask applied (hardened /proc and /sys).");
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// /dev 设置
// ══════════════════════════════════════════════════════════════════════════════

fn prune_host_devices(dev_path: &str, privileged_mask: u32) {
    if privileged_mask & PRIV_UNFILTERED != 0 {
        log_info!("[SEC] --privileged=unfiltered-dev: skipping hardware blocklist.");
        return;
    }
    let dir = match std::fs::read_dir(dev_path) {
        Ok(d) => d, Err(_) => return,
    };
    for entry in dir {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let fname_str = entry.file_name().to_string_lossy().to_string();
        if is_dangerous_node(&fname_str) {
            let path = format!("{}/{}", dev_path, fname_str);
            unsafe {
                let c = CString::new(path.as_str()).unwrap();
                libc::umount2(c.as_ptr(), libc::MNT_DETACH);
            };
            let _ = force_unlink(Path::new(&path));
            continue;
        }
        if fname_str == "dri" || fname_str == "nvidia-caps" {
            let subpath = format!("{}/{}", dev_path, fname_str);
            if let Ok(subdir) = std::fs::read_dir(&subpath) {
                for sentry in subdir.flatten() {
                    let sn = sentry.file_name().to_string_lossy().to_string();
                    if is_dangerous_node(&sn) {
                        let _ = std::fs::remove_file(format!("{}/{}", subpath, sn));
                    }
                }
            }
            if fname_str == "dri" {
                let bp = format!("{}/by-path", subpath);
                if let Ok(bpd) = std::fs::read_dir(&bp) {
                    for sentry in bpd.flatten() {
                        if sentry.file_name().to_string_lossy().contains("-card") {
                            let _ = std::fs::remove_file(format!("{}/{}", bp, sentry.file_name().to_string_lossy()));
                        }
                    }
                }
            }
        }
    }
}

pub fn setup_dev(rootfs: &str, hw_access: bool, gpu_mode: bool, privileged_mask: u32) -> io::Result<()> {
    let dev_path = format!("{}/dev", rootfs);
    std::fs::create_dir_all(&dev_path).ok();

    if hw_access {
        if domount("devtmpfs", &dev_path, "devtmpfs", libc::MS_NOSUID | libc::MS_NOEXEC, Some("mode=755")).is_ok() {
            prune_host_devices(&dev_path, privileged_mask);
            mirror_gpu_nodes(&dev_path);
        } else {
            log_warn!("Failed to mount devtmpfs, falling back to tmpfs");
            domount("none", &dev_path, "tmpfs", libc::MS_NOSUID | libc::MS_NOEXEC, Some("size=8M,mode=755"))?;
        }
    } else {
        domount("none", &dev_path, "tmpfs", libc::MS_NOSUID | libc::MS_NOEXEC, Some("size=8M,mode=755"))?;
        if gpu_mode {
            log_info!("[GPU] --gpu mode: mirroring host GPU nodes into isolated tmpfs");
            mirror_gpu_nodes(&dev_path);
        }
    }
    create_devices(rootfs)
}

pub fn create_devices(rootfs: &str) -> io::Result<()> {
    #[derive(Clone, Copy)]
    struct DevEntry {
        name: &'static str,
        mode: libc::mode_t,
        dev: libc::dev_t,
    }

    let devices = [
        DevEntry { name: "null",    mode: libc::S_IFCHR | 0o666, dev: makedev(1, 3) },
        DevEntry { name: "zero",    mode: libc::S_IFCHR | 0o666, dev: makedev(1, 5) },
        DevEntry { name: "full",    mode: libc::S_IFCHR | 0o666, dev: makedev(1, 7) },
        DevEntry { name: "random",  mode: libc::S_IFCHR | 0o666, dev: makedev(1, 8) },
        DevEntry { name: "urandom", mode: libc::S_IFCHR | 0o666, dev: makedev(1, 9) },
        DevEntry { name: "tty",     mode: libc::S_IFCHR | 0o666, dev: makedev(5, 0) },
        DevEntry { name: "console", mode: libc::S_IFCHR | 0o620, dev: makedev(5, 1) },
        DevEntry { name: "ptmx",    mode: libc::S_IFCHR | 0o666, dev: makedev(5, 2) },
    ];

    for d in &devices {
        let dev_path = format!("{}/dev/{}", rootfs, d.name);
        let path = Path::new(&dev_path);
        let _ = force_unlink(path);
        let path_c = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        if unsafe { libc::mknod(path_c.as_ptr(), d.mode, d.dev) } < 0 {
            let host_path = format!("/dev/{}", d.name);
            let _ = bind_mount(&host_path, &dev_path);
        } else {
            unsafe { libc::chmod(path_c.as_ptr(), d.mode & 0o777) };
            if d.name == "console" || d.name == "tty" {
                let _ = unsafe { libc::chown(path_c.as_ptr(), 0, constants::DEFAULT_TTY_GID) };
            }
        }
    }

    // /dev/net/tun
    let _ = std::fs::create_dir_all(format!("{}/dev/net", rootfs));
    for (sub, major, minor) in &[("net/tun", 10, 200), ("fuse", 10, 229)] {
        let dev_path = format!("{}/dev/{}", rootfs, sub);
        let path = Path::new(&dev_path);
        let _ = force_unlink(path);
        let path_c = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        if unsafe { libc::mknod(path_c.as_ptr(), libc::S_IFCHR | 0o666, makedev(*major, *minor)) } < 0 {
            let host = format!("/dev/{}", sub);
            let _ = bind_mount(&host, &dev_path);
        } else {
            unsafe { libc::chmod(path_c.as_ptr(), 0o666) };
        }
    }

    // 标准符号链接
    for (link, target) in &[
        ("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2"),
    ] {
        let tgt = format!("{}/dev/{}", rootfs, link);
        let tgt_c = CString::new(tgt.as_str()).unwrap();
        let target_c = CString::new(*target).unwrap();
        if unsafe { libc::symlink(target_c.as_ptr(), tgt_c.as_ptr()) } < 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                log_warn!("Failed to create /dev/{} symlink: {}", link, io::Error::last_os_error());
            }
    }
    Ok(())
}

fn makedev(major: u32, minor: u32) -> libc::dev_t {
    libc::makedev(major, minor)
}

// ══════════════════════════════════════════════════════════════════════════════
// devpts
// ══════════════════════════════════════════════════════════════════════════════

pub fn setup_devpts(hw_access: bool) -> io::Result<()> {
    let pts_path = "/dev/pts";
    unsafe { libc::umount2(CString::new(pts_path).unwrap().as_ptr(), libc::MNT_DETACH) };
    let _ = std::fs::create_dir_all(pts_path);

    let optbuf = format!("gid={},newinstance,ptmxmode=0666,mode=0620", constants::DEFAULT_TTY_GID);
    let optbuf2 = format!("gid={},newinstance,mode=0620", constants::DEFAULT_TTY_GID);
    let opts: [&str; 5] = [&optbuf, "newinstance,ptmxmode=0666,mode=0620", &optbuf2, "newinstance,ptmxmode=0666", "newinstance"];

    for opt in &opts {
        if domount("devpts", pts_path, "devpts", libc::MS_NOSUID | libc::MS_NOEXEC, Some(opt)).is_ok() {
            let pm_c = CString::new("/dev/pts/ptmx").unwrap();
            let ptmx_c = CString::new("/dev/ptmx").unwrap();
            if hw_access {
                if unsafe { libc::mount(pm_c.as_ptr(), ptmx_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } == 0 {
                    return Ok(());
                }
            } else {
                let _ = std::fs::remove_file("/dev/ptmx");
                let _ = write_file(Path::new("/dev/ptmx"), "");
                if unsafe { libc::mount(pm_c.as_ptr(), ptmx_c.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } == 0 {
                    return Ok(());
                }
                let _ = std::fs::remove_file("/dev/ptmx");
                if unsafe { libc::symlink(CString::new("pts/ptmx").unwrap().as_ptr(), ptmx_c.as_ptr()) } == 0
                    && Path::new("/dev/pts/ptmx").exists() { return Ok(()); }

                let _ = std::fs::remove_file("/dev/ptmx");
                if unsafe { libc::mknod(ptmx_c.as_ptr(), libc::S_IFCHR | 0o666, makedev(5, 2)) } == 0 {
                    unsafe { libc::chmod(ptmx_c.as_ptr(), 0o666) };
                    return Ok(());
                }
            }
            log_warn!("Failed to virtualize /dev/ptmx, PTYs might not work");
            return Ok(());
        }
    }
    log_error!("Failed to mount devpts with newinstance flag");
    Err(io::Error::other("devpts mount failed"))
}

// ══════════════════════════════════════════════════════════════════════════════
// OverlayFS
// ══════════════════════════════════════════════════════════════════════════════

pub fn check_volatile_mode(cfg: &Config) -> io::Result<()> {
    if !cfg.volatile_mode { return Ok(()); }
    if !grep_file(Path::new("/proc/filesystems"), "overlay").unwrap_or(false) {
        log_error!("OverlayFS is not supported by your kernel. Volatile mode cannot be used.");
        return Err(io::Error::other("OverlayFS not supported"));
    }
    let mp_c = CString::new(cfg.img_mount_point.to_string_lossy().as_bytes()).unwrap();
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(mp_c.as_ptr(), &mut sfs) } == 0 && sfs.f_type == 0xF2F5_2010 {
        log_error!("Volatile mode cannot be used: Your rootfs is on f2fs.");
        log_error!("Tip: Use a rootfs image (-i) instead of a directory for volatile mode on f2fs partitions.");
        return Err(io::Error::other("f2fs not supported for overlay lowerdir"));
    }
    Ok(())
}

pub fn setup_volatile_overlay(cfg: &mut Config) -> io::Result<()> {
    let base = format!("{}/{}/{}", get_runtime_dir(), constants::RUNTIME_VOLATILE_SUBDIR, cfg.container_name);
    mkdir_p(Path::new(&base), 0o755)?;
    cfg.volatile_dir = base.clone().into();
    domount("none", &base, "tmpfs", 0, Some("size=50%,mode=755"))?;

    let upper = format!("{}/upper", base);
    let work = format!("{}/work", base);
    let merged = format!("{}/merged", base);
    std::fs::create_dir_all(&upper).ok();
    std::fs::create_dir_all(&work).ok();
    std::fs::create_dir_all(&merged).ok();

    let opts = format!(
        "lowerdir={},upperdir={}/upper,workdir={}/work,context=\"{}\"",
        cfg.img_mount_point.display(), base, base, constants::ANDROID_TMPFS_CONTEXT
    );
    if opts.len() >= 32768 {
        log_error!("OverlayFS options too long");
        cleanup_volatile_overlay(cfg);
        return Err(io::Error::other("overlay options too long"));
    }
    if domount("overlay", &merged, "overlay", 0, Some(&opts)).is_err() {
        log_error!("OverlayFS mount failed.");
        unsafe { libc::umount2(CString::new(base.as_str()).unwrap().as_ptr(), libc::MNT_DETACH) };
        cleanup_volatile_overlay(cfg);
        return Err(io::Error::other("overlay mount failed"));
    }
    cfg.img_mount_point = merged.into();
    Ok(())
}

fn is_mount_in_namespace(path: &str) -> bool {
    let content = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(c) => c, Err(_) => return false,
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 && fields[4] == path { return true; }
    }
    false
}

pub fn cleanup_volatile_overlay(cfg: &mut Config) -> i32 {
    if cfg.volatile_dir.as_os_str().is_empty() { return 0; }
    let merged = format!("{}/merged", cfg.volatile_dir.display());
    let base_str = cfg.volatile_dir.to_string_lossy().to_string();
    if is_mount_in_namespace(&merged) || is_mount_in_namespace(&base_str) {
        unsafe { libc::sync() };
        unsafe {
            libc::umount(CString::new(merged.as_str()).unwrap().as_ptr());
            libc::umount(CString::new(base_str.as_str()).unwrap().as_ptr());
        }
    }
    std::thread::sleep(std::time::Duration::from_micros((constants::RETRY_DELAY_US / 2) as u64));
    let r = remove_recursive(Path::new(&cfg.volatile_dir));
    cfg.volatile_dir = Path::new("").into();
    if r.is_err() { -1 } else { 0 }
}

// ══════════════════════════════════════════════════════════════════════════════
// 自定义 bind mount
// ══════════════════════════════════════════════════════════════════════════════

pub fn setup_custom_binds(cfg: &mut Config, rootfs: &str) -> i32 {
    if cfg.binds.is_empty() { return 0; }
    sort_bind_mounts(cfg);

    for bind in &cfg.binds {
        let tgt = format!("{}{}", rootfs, bind.dest.display());
        let tgt_path = Path::new(&tgt);

        if let Some(parent) = tgt_path.parent() {
            if path_has_symlink(parent) {
                log_error!("Security Violation: symlink in bind target path {}", parent.display());
                continue;
            }
            mkdir_p(parent, 0o755).ok();
        }
        if bind_mount(&bind.src.to_string_lossy(), &tgt).is_err() {
            log_warn!("Failed to bind mount {} on {} (skipping)", bind.src.display(), tgt);
            continue;
        }
        if !is_subpath(rootfs, &tgt) {
            log_error!("Security Violation: Bind destination {} escapes rootfs {}!", tgt, rootfs);
            unsafe { libc::umount2(CString::new(tgt.as_str()).unwrap().as_ptr(), libc::MNT_DETACH) };
            continue;
        }
        if bind.ro {
            let tgt_c = CString::new(tgt.as_str()).unwrap();
            if unsafe {
                libc::mount(std::ptr::null(), tgt_c.as_ptr(), std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY, std::ptr::null())
            } < 0 {
                log_warn!("Failed to remount {} read-only: {}", tgt, io::Error::last_os_error());
            }
        }
    }
    0
}

// ══════════════════════════════════════════════════════════════════════════════
// Loop 设备管理
// ══════════════════════════════════════════════════════════════════════════════

fn detect_fs_type(img_path: &str) -> Option<&'static str> {
    let img_c = CString::new(img_path).unwrap();
    let fd = unsafe { libc::open(img_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 { return None; }

    let mut buf = [0u8; 8];
    if unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 2, 0x438) } == 2 {
        let m = buf[0] as u16 | ((buf[1] as u16) << 8);
        if m == 0xEF53 { unsafe { libc::close(fd) }; return Some("ext4"); }
    }
    if unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 8, 0x10040) } == 8
        && &buf == b"_BHRfS_M" { unsafe { libc::close(fd) }; return Some("btrfs"); }
    unsafe { libc::close(fd) };
    None
}

fn open_loop_dev(devnr: i32) -> io::Result<(RawFd, String)> {
    let android_path = format!("/dev/block/loop{}", devnr);
    for _ in 0..5 {
        let p = CString::new(android_path.as_str()).unwrap();
        let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 { return Ok((fd, android_path)); }
        std::thread::sleep(std::time::Duration::from_micros(100_000));
    }
    let desktop_path = format!("/dev/loop{}", devnr);
    let dp = CString::new(desktop_path.as_str()).unwrap();
    let fd = unsafe { libc::open(dp.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd >= 0 { return Ok((fd, desktop_path)); }

    // mknod fallback
    let dev = libc::makedev(7, devnr as libc::c_uint);
    if unsafe { libc::mknod(dp.as_ptr(), libc::S_IFBLK | 0o660, dev) } == 0 {
        let fd2 = unsafe { libc::open(dp.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd2 >= 0 { return Ok((fd2, desktop_path)); }
    }
    Err(io::Error::last_os_error())
}

fn loop_attach(img_path: &str) -> io::Result<(RawFd, String)> {
    let ctl_c = CString::new("/dev/loop-control").unwrap();
    let ctl_fd = unsafe { libc::open(ctl_c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if ctl_fd < 0 {
        log_error!("open /dev/loop-control: {}", io::Error::last_os_error());
        return Err(io::Error::last_os_error());
    }
    let devnr = unsafe { libc::ioctl(ctl_fd, LOOP_CTL_GET_FREE) };
    unsafe { libc::close(ctl_fd) };
    if devnr < 0 {
        log_error!("LOOP_CTL_GET_FREE: {}", io::Error::last_os_error());
        return Err(io::Error::last_os_error());
    }

    let (loop_fd, loop_path) = open_loop_dev(devnr as i32)?;

    let img_c = CString::new(img_path).unwrap();
    let img_fd = unsafe { libc::open(img_c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if img_fd < 0 {
        log_error!("open image {}: {}", img_path, io::Error::last_os_error());
        unsafe { libc::close(loop_fd) };
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::ioctl(loop_fd, LOOP_SET_FD, img_fd) } < 0 {
        log_error!("LOOP_SET_FD: {}", io::Error::last_os_error());
        unsafe { libc::close(img_fd); libc::close(loop_fd); }
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::close(img_fd) };

    let mut li: LoopInfo64 = unsafe { std::mem::zeroed() };
    li.lo_flags = LO_FLAGS_AUTOCLEAR;
    let name_bytes = img_path.as_bytes();
    for (i, &b) in name_bytes.iter().enumerate().take(63) {
        li.lo_file_name[i] = b;
    }
    if unsafe { libc::ioctl(loop_fd, LOOP_SET_STATUS64, &li) } < 0 {
        log_warn!("LOOP_SET_STATUS64: {} (continuing)", io::Error::last_os_error());
    }
    Ok((loop_fd, loop_path))
}

fn loop_detach(loop_dev: &str) {
    if loop_dev.is_empty() { return; }
    let p = CString::new(loop_dev).unwrap();
    let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 { return; }
    unsafe { libc::ioctl(fd, LOOP_CLR_FD, 0) };
    unsafe { libc::close(fd) };
}

fn get_backing_dev(mnt: &str) -> Option<String> {
    let content = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == mnt { return Some(parts[0].to_string()); }
    }
    None
}

// ══════════════════════════════════════════════════════════════════════════════
// Rootfs 镜像挂载 / 卸载
// ══════════════════════════════════════════════════════════════════════════════

pub fn mount_rootfs_img(img_path: &str, mount_point: &mut String, name: &str) -> io::Result<()> {
    let mp = find_available_mountpoint(name)?;
    let fstype = match detect_fs_type(img_path) {
        Some(f) => f,
        None => {
            log_warn!("Unknown filesystem in {}. Only ext4 and btrfs are supported.", img_path);
            return Err(io::Error::other("unknown filesystem type"));
        }
    };

    unsafe { libc::sync() };
    std::thread::sleep(std::time::Duration::from_micros(constants::RETRY_DELAY_US as u64));

    let mnt_flags = libc::MS_NOATIME | libc::MS_NODIRATIME;
    let mnt_data: Option<&str> = if fstype == "ext4" { Some("nodelalloc,errors=remount-ro,init_itable=0") } else { None };

    for attempt in 0..3 {
        if attempt == 0 {
            log_info!("Mounting {} rootfs image {} on {}...", fstype, img_path, mp);
        } else {
            log_info!("Mounting {} rootfs image {} on {} (Attempt {}/3)...", fstype, img_path, mp, attempt + 1);
        }

        let is_blk = Path::new(img_path).metadata().map(|m| m.file_type().is_block_device()).unwrap_or(false);
        let (final_src, loop_fd) = if is_blk {
            (img_path.to_string(), -1)
        } else {
            match loop_attach(img_path) {
                Ok((fd, path)) => (path, fd),
                Err(_) => {
                    if attempt < 2 {
                        unsafe { libc::sync() };
                        std::thread::sleep(std::time::Duration::from_micros((constants::RETRY_DELAY_US * 5) as u64));
                    }
                    continue;
                }
            }
        };

        let src_c = CString::new(final_src.as_str()).unwrap();
        let mp_c = CString::new(mp.as_str()).unwrap();
        let fstype_c = CString::new(fstype).unwrap();
        let data_c = mnt_data.map(|d| CString::new(d).unwrap_or_default());
        let data_ptr = data_c.as_ref().map(|c| c.as_ptr() as *const libc::c_void).unwrap_or(std::ptr::null());

        let ret = unsafe { libc::mount(src_c.as_ptr(), mp_c.as_ptr(), fstype_c.as_ptr(), mnt_flags, data_ptr) };
        if loop_fd >= 0 { unsafe { libc::close(loop_fd) }; }

        if ret == 0 {
            unsafe { libc::mount(std::ptr::null(), mp_c.as_ptr(), std::ptr::null(), libc::MS_REMOUNT | mnt_flags, data_ptr) };
            *mount_point = mp;
            return Ok(());
        }

        // mount failed
        let final_src_for_log = final_src.clone();
        if loop_fd >= 0 { loop_detach(&final_src_for_log); }
        log_warn!("mount({}, {}) failed: {}", final_src_for_log, fstype, io::Error::last_os_error());

        if attempt < 2 {
            log_info!("Retrying in 1s...");
            unsafe { libc::sync() };
            std::thread::sleep(std::time::Duration::from_micros((constants::RETRY_DELAY_US * 5) as u64));
        }
    }
    log_error!("Failed to mount image {} after 3 attempts", img_path);
    Err(io::Error::other("image mount failed after 3 retries"))
}

pub fn unmount_rootfs_img(mount_point: &str, silent: bool) -> i32 {
    if mount_point.is_empty() { return 0; }
    let loop_dev = get_backing_dev(mount_point).unwrap_or_default();

    unsafe { libc::sync() };
    let mp_c = CString::new(mount_point).unwrap();
    unsafe { libc::umount2(mp_c.as_ptr(), libc::MNT_DETACH) };

    if !loop_dev.is_empty() { loop_detach(&loop_dev); }

    unsafe { libc::sync() };
    std::thread::sleep(std::time::Duration::from_micros(constants::RETRY_DELAY_US as u64));
    if is_mountpoint(Path::new(mount_point)) {
        unsafe { libc::umount2(mp_c.as_ptr(), libc::MNT_DETACH | libc::MNT_FORCE) };
        std::thread::sleep(std::time::Duration::from_micros((constants::RETRY_DELAY_US / 2) as u64));
    }

    let still_mounted = is_mountpoint(Path::new(mount_point));
    if std::fs::remove_dir(mount_point).is_ok() || !still_mounted {
        if !silent { log_info!("Unmounted rootfs image from {}.", mount_point); }
    } else if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        && !silent { log_warn!("Cleanup warning: {} is still busy/mounted.", mount_point); }
    0
}

// ══════════════════════════════════════════════════════════════════════════════
// 宿主机 devpts 修复
// ══════════════════════════════════════════════════════════════════════════════

pub fn fix_host_ptys() -> io::Result<()> {
    let pts_path = "/dev/pts";
    if is_mountpoint(Path::new(pts_path)) { return Ok(()); }
    std::fs::create_dir_all(pts_path).ok();

    let ret = unsafe {
        let s = CString::new("devpts").unwrap();
        let t = CString::new(pts_path).unwrap();
        let o = CString::new("gid=5,mode=620").unwrap();
        libc::mount(s.as_ptr(), t.as_ptr(), s.as_ptr(), libc::MS_NOSUID | libc::MS_NOEXEC,
            o.as_ptr() as *const libc::c_void)
    };
    if ret < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
        log_warn!("Failed to mount host devpts: {}", io::Error::last_os_error());
        return Err(io::Error::last_os_error());
    }
    log_info!("Host devpts mounted successfully (Recovery fix).");
    Ok(())
}
