//! 资源可见性虚拟化 —— 对应原 virtualize.c。
//!
//! 基于 cgroup 限制虚拟化 /proc 文件（meminfo、cpuinfo、stat、uptime、loadavg）
//! 和 /sys/devices/system/cpu 树。

use std::io;
use std::path::Path;

use crate::constants;
use crate::types::Config;
use crate::utils::{read_file, sanitize_container_name, write_file};
use crate::{log_info, log_warn};

const VPROC_PATH: &str = concat!("/run/", env!("CARGO_PKG_NAME"), "/vproc");

// ── 跨模块引用（mount.rs 的真实实现）──
use crate::mount::{bind_mount, domount};

// ══════════════════════════════════════════════════════════════════════════════
// 内部辅助函数
// ══════════════════════════════════════════════════════════════════════════════

fn container_cpus(cfg: &Config) -> i32 {
    let host = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as i32;
    let quota = cfg.cpu_quota.unwrap_or(0);
    let period = cfg.cpu_period.unwrap_or(0);
    if quota <= 0 || period <= 0 { return host; }
    let n = ((quota + period - 1) / period) as i32;
    n.clamp(1, host)
}

fn read_cg_ll(container_name: &str, file: &str) -> i64 {
    let safe_name = sanitize_container_name(container_name);
    let path = format!("/sys/fs/cgroup/{}/{}/{}", constants::PROJECT_NAME, safe_name, file);
    let buf = match read_file(Path::new(&path)) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    if buf == "max" { return -1; }
    buf.parse().unwrap_or(-1)
}

fn write_inplace(pid: libc::pid_t, subpath: &str, buf: &[u8]) -> io::Result<()> {
    let fd = crate::utils::safe_openat_proc(pid, subpath, libc::O_WRONLY, 0)?;

    // 安全检查：必须是常规文件
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        unsafe { libc::close(fd) };
        return Err(io::Error::other("not a regular file"));
    }

    // 安全检查：必须在 tmpfs 上
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut sfs) } < 0 || sfs.f_type != libc::TMPFS_MAGIC {
        unsafe { libc::close(fd) };
        return Err(io::Error::other("not on tmpfs"));
    }

    let w = unsafe { crate::utils::write_all_raw(fd, buf) }?;
    if w == buf.len() {
        unsafe { libc::ftruncate(fd, buf.len() as libc::off_t) };
    }
    unsafe { libc::close(fd) };
    if w == buf.len() { Ok(()) } else { Err(io::Error::other("partial write")) }
}

// ══════════════════════════════════════════════════════════════════════════════
// 内容生成器
// ══════════════════════════════════════════════════════════════════════════════

fn gen_meminfo(cfg: &Config) -> Option<Vec<u8>> {
    let mem_limit = cfg.memory_limit.unwrap_or(0);
    let mem_used = read_cg_ll(&cfg.container_name, "memory.current").max(0);

    let host_content = std::fs::read_to_string("/proc/meminfo").ok()?;

    let host_total_kb: i64 = host_content.lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l[9..].split_whitespace().next().and_then(|s| s.parse().ok()))
        .unwrap_or(0);

    let ratio = if mem_limit > 0 && host_total_kb > 0 {
        mem_limit as f64 / (host_total_kb as f64 * 1024.0)
    } else { 1.0 };

    let lim_kb = mem_limit / 1024;

    // memory.stat for accurate anon/file/slab
    let (cg_anon, cg_file, cg_slab) = {
        let safe_name = sanitize_container_name(&cfg.container_name);
        let sp = format!("/sys/fs/cgroup/{}/{}/memory.stat", constants::PROJECT_NAME, safe_name);
        if let Ok(s) = read_file(Path::new(&sp)) {
            let parse = |key: &str| -> i64 {
                s.lines().find(|l| l.starts_with(key))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok()).unwrap_or(-1)
            };
            (parse("anon "), parse("file "), parse("slab "))
        } else { (-1, -1, -1) }
    };

    let mut out = String::with_capacity(16384);

    for line in host_content.lines() {
        if let Some((key, rest)) = line.split_once(':') {
            let key = key.trim();
            let rest = rest.trim();
            if let Some(val_str) = rest.split_whitespace().next() {
                if let Ok(val) = val_str.parse::<i64>() {
                    let has_kb = rest.contains(" kB");
                    let mut new_val = val;

                    if mem_limit > 0 {
                        new_val = match key {
                            "MemTotal" => lim_kb,
                            "MemFree" => ((mem_limit - mem_used) / 1024).max(0),
                            "MemAvailable" => (lim_kb - mem_used / 1024).max(0),
                            "SwapTotal" | "SwapFree" => 0,
                            "AnonPages" if cg_anon >= 0 => cg_anon / 1024,
                            "Cached" | "Mapped" if cg_file >= 0 => cg_file / 1024,
                            "Slab" if cg_slab >= 0 => cg_slab / 1024,
                            _ => (val as f64 * ratio) as i64,
                        };
                        if has_kb && new_val > lim_kb { new_val = lim_kb; }
                    }
                    use std::fmt::Write;
                    let _ = writeln!(out, "{:<16}{:11} kB", format!("{}:", key), new_val);
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out.into_bytes())
}

fn gen_cpuinfo(cfg: &Config) -> Option<Vec<u8>> {
    let max_cpus = container_cpus(cfg) as usize;
    let content = std::fs::read_to_string("/proc/cpuinfo").ok()?;

    let mut out = String::with_capacity(65536);
    let mut cur_cpu: i32 = -1;

    for line in content.lines() {
        if line.starts_with("processor") {
            if let Some(s) = line.split(':').nth(1) {
                cur_cpu = s.trim().parse().unwrap_or(-1);
            }
        }
        if cur_cpu >= max_cpus as i32 { break; }
        out.push_str(line);
        out.push('\n');
    }
    Some(out.into_bytes())
}

fn gen_stat(cfg: &Config) -> Option<Vec<u8>> {
    let max_cpus = container_cpus(cfg);
    let content = std::fs::read_to_string("/proc/stat").ok()?;

    let mut su = 0u64; let mut sn = 0u64; let mut ss = 0u64; let mut si = 0u64;
    let mut sio = 0u64; let mut sir = 0u64; let mut ssoft = 0u64;
    let mut sst = 0u64; let mut sgu = 0u64; let mut sgn = 0u64;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("cpu") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 10 {
                if let (Ok(id), vals @ [..]) = (parts[0].parse::<i32>(), &parts[1..]) {
                    if id < max_cpus {
                        su += vals[0].parse::<u64>().unwrap_or(0);
                        sn += vals[1].parse::<u64>().unwrap_or(0);
                        ss += vals[2].parse::<u64>().unwrap_or(0);
                        si += vals[3].parse::<u64>().unwrap_or(0);
                        sio += vals[4].parse::<u64>().unwrap_or(0);
                        sir += vals[5].parse::<u64>().unwrap_or(0);
                        ssoft += vals[6].parse::<u64>().unwrap_or(0);
                        sst += vals[7].parse::<u64>().unwrap_or(0);
                        sgu += vals[8].parse::<u64>().unwrap_or(0);
                        sgn += vals[9].parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }
    }

    let mut out = String::with_capacity(65536);
    let mut agg_done = false;

    for line in content.lines() {
        if line.starts_with("cpu ") {
            if !agg_done {
                use std::fmt::Write;
                let _ = writeln!(out, "cpu  {} {} {} {} {} {} {} {} {} {}",
                    su, sn, ss, si, sio, sir, ssoft, sst, sgu, sgn);
                agg_done = true;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("cpu") {
            if let Ok(id) = rest.split_whitespace().next().unwrap_or("").parse::<i32>() {
                if id >= max_cpus { continue; }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out.into_bytes())
}

fn cg_cpu_busy_secs(container_name: &str) -> f64 {
    let safe_name = sanitize_container_name(container_name);
    let path = format!("/sys/fs/cgroup/{}/{}/cpu.stat", constants::PROJECT_NAME, safe_name);
    let buf = match read_file(Path::new(&path)) { Ok(b) => b, Err(_) => return -1.0 };
    buf.lines()
        .find(|l| l.starts_with("usage_usec "))
        .and_then(|l| l[11..].trim().parse::<i64>().ok())
        .map(|u| u as f64 / 1e6)
        .unwrap_or(-1.0)
}

fn container_start_time_secs(pid: libc::pid_t) -> f64 {
    let stat = match std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s,
        Err(_) => return -1.0,
    };
    let after_comm = match stat.find(") ") {
        Some(p) => p,
        None => return -1.0,
    };
    let fields: Vec<&str> = stat[after_comm + 2..].split_whitespace().collect();
    let starttime: u64 = match fields.get(19).and_then(|s| s.parse().ok()) {
        Some(st) => st,
        None => return -1.0,
    };
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1);
    if starttime == 0 { return -1.0; }
    starttime as f64 / ticks as f64
}

fn gen_uptime(cfg: &Config) -> Option<Vec<u8>> {
    let mut boot: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) };
    let boottime = boot.tv_sec as f64 + boot.tv_nsec as f64 / 1e9;

    let mut up = -1.0;
    if cfg.container_pid.unwrap_or(0) > 0 {
        let ps = container_start_time_secs(cfg.container_pid.unwrap());
        if ps > 0.0 { up = boottime - ps; }
    }
    if up < 0.0 {
        up = boottime - (cfg.start_time.tv_sec as f64 + cfg.start_time.tv_nsec as f64 / 1e9);
    }
    if up < 0.0 { up = 0.0; }

    let ccpus = container_cpus(cfg) as f64;
    let busy = cg_cpu_busy_secs(&cfg.container_name);
    let idle = if busy >= 0.0 { up * ccpus - busy } else { up * ccpus * 0.1 };
    let idle = idle.max(0.0);

    Some(format!("{:.2} {:.2}\n", up, idle).into_bytes())
}

fn gen_loadavg(cfg: &Config) -> Option<Vec<u8>> {
    let content = std::fs::read_to_string("/proc/loadavg").ok()?;
    let parts: Vec<f64> = content.split_whitespace().filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 5 { return None; }
    let (l1, l5, l15, run, tot) = (parts[0], parts[1], parts[2], parts[3] as i32, parts[4] as i32);

    let hcpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as i32;
    let ccpus = container_cpus(cfg);
    let r = ccpus as f64 / hcpus as f64;

    let srun = (run as f64 * r) as i32;
    let stot = (tot as f64 * r) as i32;

    Some(format!("{:.2} {:.2} {:.2} {}/{} 0\n", l1 * r, l5 * r, l15 * r, srun.max(0), stot.max(1)).into_bytes())
}

/// 内容生成器函数类型别名
type GenFn = fn(&Config) -> Option<Vec<u8>>;

// ══════════════════════════════════════════════════════════════════════════════
// 公共 API
// ══════════════════════════════════════════════════════════════════════════════

pub fn get_pid_ns_inode(pid: libc::pid_t) -> u64 {
    let path = format!("/proc/{}/ns/pid", pid);
    std::fs::metadata(&path).map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    }).unwrap_or(0)
}

fn bind_vfile(vpath: &str, target: &str, content: &[u8]) {
    if write_file(Path::new(vpath), &String::from_utf8_lossy(content)).is_err() { return; }
    if !Path::new(target).exists() {
        let _ = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(target);
    }
    if bind_mount(vpath, target).is_err() {
        log_warn!("[VIRT] bind_mount {} -> {} failed", vpath, target);
    }
}

fn virtualize_affinity(cfg: &Config) {
    let n = container_cpus(cfg);
    let host = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as i32;
    if n >= host || n <= 0 { return; }

    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut mask) } < 0 { return; }

    let mut new_mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let mut count = 0;
    for i in 0..libc::CPU_SETSIZE {
        if count >= n { break; }
        if unsafe { libc::CPU_ISSET(i as usize, &mask) } {
            unsafe { libc::CPU_SET(i as usize, &mut new_mask) };
            count += 1;
        }
    }
    if count > 0 {
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &new_mask) };
    }
}

pub fn virtualize_init(cfg: &Config) -> io::Result<()> {
    let has_mem = cfg.memory_limit.unwrap_or(0) > 0;
    let has_cpu = cfg.cpu_quota.unwrap_or(0) > 0;

    if has_cpu { virtualize_affinity(cfg); }

    crate::utils::mkdir_p(Path::new(VPROC_PATH), 0o755)?;
    domount("none", VPROC_PATH, "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=755,size=1M"))?;

    // /proc 文件虚拟化
    type GenFn = fn(&Config) -> Option<Vec<u8>>;
    let proc_files: &[(&str, GenFn, bool)] = &[
        ("meminfo", gen_meminfo, has_mem),
        ("cpuinfo", gen_cpuinfo, has_cpu),
        ("stat", gen_stat, has_cpu),
        ("uptime", gen_uptime, true),
        ("loadavg", gen_loadavg, true),
    ];

    for (name, gen, enabled) in proc_files {
        if !enabled { continue; }
        if let Some(buf) = gen(cfg) {
            let vpath = format!("{}/{}", VPROC_PATH, name);
            let target = format!("/proc/{}", name);
            bind_vfile(&vpath, &target, &buf);
        }
    }

    // CPU sysfs for nproc/htop
    if has_cpu {
        let sysfs_base = format!("{}/cpu_sysfs", VPROC_PATH);
        crate::utils::mkdir_p(Path::new(&sysfs_base), 0o755)?;

        let n = container_cpus(cfg) as usize;
        for i in 0..n {
            let vcpu = format!("{}/cpu{}", sysfs_base, i);
            let realcpu = format!("/sys/devices/system/cpu/cpu{}", i);
            if Path::new(&realcpu).exists() {
                let _ = std::fs::create_dir(&vcpu);
                let _ = bind_mount(&realcpu, &vcpu);
            }
        }

        for name in &["online", "possible", "present"] {
            let vpath = format!("{}/{}", sysfs_base, name);
            let content = if n == 1 { "0\n".to_string() } else { format!("0-{}\n", n - 1) };
            let _ = write_file(Path::new(&vpath), &content);
        }

        let _ = bind_mount(&sysfs_base, "/sys/devices/system/cpu");
    }

    log_info!("[VIRT] Resource virtualization active (mem={}, cpu={}, uptime=1, loadavg=1)", has_mem, has_cpu);
    Ok(())
}

pub fn virtualize_update(cfg: &Config) {
    if cfg.container_pid.unwrap_or(0) <= 0 { return; }

    // PID-recycling 防护
    if cfg.ns_inode != 0 {
        let live = get_pid_ns_inode(cfg.container_pid.unwrap());
        if live != cfg.ns_inode { return; }
    }

    let vproc_dir = format!("/proc/{}/root{}", cfg.container_pid.unwrap(), VPROC_PATH);
    if !Path::new(&vproc_dir).is_dir() { return; }

    let has_mem = cfg.memory_limit.unwrap_or(0) > 0;
    let has_cpu = cfg.cpu_quota.unwrap_or(0) > 0;

    let dyn_files: &[(&str, GenFn, bool)] = &[
        ("meminfo", gen_meminfo, has_mem),
        ("stat", gen_stat, has_cpu),
        ("uptime", gen_uptime, true),
        ("loadavg", gen_loadavg, true),
    ];

    for (name, gen, enabled) in dyn_files {
        if !enabled { continue; }
        if let Some(buf) = gen(cfg) {
            let subpath = format!("{}/{}", VPROC_PATH, name);
            let _ = write_inplace(cfg.container_pid.unwrap(), &subpath, &buf);
        }
    }
}
