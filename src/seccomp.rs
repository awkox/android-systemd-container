//! Seccomp BPF 过滤器 —— 对应原 seccomp.c。
//!
//! 实现两个 seccomp 过滤器：
//! 1. `seccomp_apply_minimal()` —— 最小过滤器，阻止宿主机内核接管向量
//! 2. `android_seccomp_setup()` —— Android 兼容性过滤
//!
//! # 架构支持
//! 通过 `#[cfg()]` 属性在编译时选择正确的审计架构常量和系统调用编号。

use std::io;
use std::mem;

use crate::types::PRIV_NOSEC;
use crate::utils::get_kernel_version;
use crate::{log_info, log_warn};

// ══════════════════════════════════════════════════════════════════════════════
// BPF 指令构建辅助函数
// ══════════════════════════════════════════════════════════════════════════════

/// 构建 BPF 语句指令（无跳转偏移）。
/// 等价于 C 宏 `BPF_STMT(code, k)`
#[inline]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

/// 构建 BPF 跳转指令。
/// 等价于 C 宏 `BPF_JUMP(code, k, jt, jf)`
#[inline]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// 构建 seccomp 返回值：ERRNO(errno) 动作。
/// `SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA)`
#[inline]
fn seccomp_errno(errno: libc::c_int) -> u32 {
    libc::SECCOMP_RET_ERRNO | ((errno as u32) & libc::SECCOMP_RET_DATA)
}

// ══════════════════════════════════════════════════════════════════════════════
// 架构常量（libc crate 不导出 AUDIT_ARCH_*，需手动定义）
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "arm")]
const AUDIT_ARCH: u32 = 0x4000_0028; // AUDIT_ARCH_ARM
#[cfg(target_arch = "x86")]
const AUDIT_ARCH: u32 = 0x4000_0003; // AUDIT_ARCH_I386
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "arm", target_arch = "x86")))]
const AUDIT_ARCH: u32 = 0;

/// x86-64 是否应阻止 x32 ABI
#[cfg(target_arch = "x86_64")]
const BLOCK_X32_ABI: bool = true;
#[cfg(not(target_arch = "x86_64"))]
const BLOCK_X32_ABI: bool = false;

// ══════════════════════════════════════════════════════════════════════════════
// 系统调用存在性守卫（条件编译 `cfg!()` + 编译时常量）
// ══════════════════════════════════════════════════════════════════════════════

const HAS_KEXEC_FILE_LOAD: bool = cfg!(any(target_arch = "aarch64", target_arch = "x86_64"));
const HAS_CLONE3: bool = true;
const HAS_SETTIMEOFDAY: bool = cfg!(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"));
const HAS_ADJTIMEX: bool = cfg!(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm"));
const HAS_CLOCK_SETTIME: bool = cfg!(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm"));
const HAS_CLOCK_ADJTIME: bool = cfg!(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"));
const HAS_SYSLOG: bool = cfg!(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm"));

// ══════════════════════════════════════════════════════════════════════════════
// BPF 指令常量（类型统一为 u16）
// ══════════════════════════════════════════════════════════════════════════════

const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const BPF_JMP_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const BPF_JMP_JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const BPF_JMP_JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

// ══════════════════════════════════════════════════════════════════════════════
// 最小 seccomp 过滤器
// ══════════════════════════════════════════════════════════════════════════════

/// 应用最小 seccomp BPF 过滤器。
///
/// 阻止模块加载、kexec、clone3、用户命名空间创建、AF_ALG、时钟修改、syslog。
/// `PRIV_NOSEC` 标志跳过全部 seccomp。
pub fn seccomp_apply_minimal(privileged_mask: u32) -> io::Result<()> {
    if privileged_mask & PRIV_NOSEC != 0 {
        return Ok(());
    }

    let arch_offset = mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr_offset = mem::offset_of!(libc::seccomp_data, nr) as u32;
    let args_offset = mem::offset_of!(libc::seccomp_data, args) as u32;

    let mut filter: Vec<libc::sock_filter> = Vec::with_capacity(78);

    // 1. 架构验证（不匹配则 KILL）
    filter.push(bpf_stmt(BPF_LD_W_ABS, arch_offset));
    filter.push(bpf_jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0));
    filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));

    // 2. 加载系统调用编号
    filter.push(bpf_stmt(BPF_LD_W_ABS, nr_offset));

    // 3. x86-64: 阻止 x32 ABI
    if BLOCK_X32_ABI {
        filter.push(bpf_jump(BPF_JMP_JGE_K, 0x4000_0000, 0, 1));
        filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    }

    if privileged_mask & PRIV_NOSEC == 0 {
        // 4. 内核模块加载
        for &nr in &[libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module] {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, nr as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
        }

        // 5. kexec
        filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_kexec_load as u32, 0, 1));
        filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
        if HAS_KEXEC_FILE_LOAD {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_kexec_file_load as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
        }

        // 6. 阻止 clone3
        if HAS_CLONE3 {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::ENOSYS)));
        }

        // 7. unshare(CLONE_NEWUSER)
        filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_unshare as u32, 0, 4));
        filter.push(bpf_stmt(BPF_LD_W_ABS, args_offset));
        filter.push(bpf_jump(BPF_JMP_JSET_K, 0x1000_0000, 0, 1)); // CLONE_NEWUSER
        filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        filter.push(bpf_stmt(BPF_LD_W_ABS, nr_offset)); // 重载 nr

        // 8. clone(CLONE_NEWUSER)
        filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 3));
        filter.push(bpf_stmt(BPF_LD_W_ABS, args_offset));
        filter.push(bpf_jump(BPF_JMP_JSET_K, 0x1000_0000, 0, 1));
        filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));

        // 9. CVE-2026-31431 缓解：阻止 socket(AF_ALG)
        filter.push(bpf_stmt(BPF_LD_W_ABS, nr_offset));
        filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_socket as u32, 0, 4));
        filter.push(bpf_stmt(BPF_LD_W_ABS, args_offset));
        filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::AF_ALG as u32, 0, 1));
        filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        filter.push(bpf_stmt(BPF_LD_W_ABS, nr_offset)); // 重载 nr

        // 10. 阻止宿主机时钟修改
        if HAS_SETTIMEOFDAY {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_settimeofday as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }
        if HAS_ADJTIMEX {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_adjtimex as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }
        if HAS_CLOCK_SETTIME {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clock_settime as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }
        if HAS_CLOCK_ADJTIME {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clock_adjtime as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }
        #[cfg(any(target_arch = "arm", target_arch = "x86"))]
        {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clock_settime64 as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }

        // 10b. 阻止通过 syslog(2) 访问宿主机内核日志
        if HAS_SYSLOG {
            filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_syslog as u32, 0, 1));
            filter.push(bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)));
        }
    }

    // 允许其他所有系统调用
    filter.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));

    // 应用过滤器
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog, 0, 0) } < 0 {
        log_warn!("[SEC] Failed to apply minimal seccomp filter: {}", io::Error::last_os_error());
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// Android seccomp 设置
// ══════════════════════════════════════════════════════════════════════════════

/// 为 Android 兼容性应用 seccomp BPF 过滤器。
///
/// 1. Keyring 兼容（ENOSYS）：旧内核（<5.0）上避免遍历缺失的系统调用。
/// 2. 死锁盾（EPERM）：仅当 `block_nested_ns` 为 true 时阻止命名空间创建。
pub fn android_seccomp_setup(block_nested_ns: bool, privileged_mask: u32) -> io::Result<()> {
    if privileged_mask & PRIV_NOSEC != 0 {
        return Ok(());
    }

    let (major, _minor) = get_kernel_version().unwrap_or((0, 0));

    // 命名空间掩码
    const NS_MASK: u32 = 0x7E02_0000;

    if !block_nested_ns && major >= 5 {
        return Ok(());
    }

    let arch_offset = mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr_offset = mem::offset_of!(libc::seccomp_data, nr) as u32;
    let args_offset = mem::offset_of!(libc::seccomp_data, args) as u32;

    // ── 基础过滤器：架构检查 + 加载 nr ──
    let filter_base = vec![
        bpf_stmt(BPF_LD_W_ABS, arch_offset),
        bpf_jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0),
        bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        bpf_stmt(BPF_LD_W_ABS, nr_offset),
    ];

    // ── keyring 过滤器（内核 < 5.0）──
    let filter_keyring = vec![
        bpf_jump(BPF_JMP_JEQ_K, libc::SYS_keyctl as u32, 0, 1),
        bpf_stmt(BPF_RET_K, seccomp_errno(libc::ENOSYS)),
    ];

    // ── 命名空间死锁盾 ──
    let filter_ns = vec![
        bpf_jump(BPF_JMP_JEQ_K, libc::SYS_unshare as u32, 1, 0),
        bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 3),
        bpf_stmt(BPF_LD_W_ABS, args_offset),
        bpf_jump(BPF_JMP_JSET_K, NS_MASK, 0, 1),
        bpf_stmt(BPF_RET_K, seccomp_errno(libc::EPERM)),
    ];

    // ── 允许所有其他调用 ──
    let filter_allow = vec![bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW)];

    // 组合过滤器
    let mut final_filter: Vec<libc::sock_filter> = Vec::new();
    final_filter.extend_from_slice(&filter_base);

    if major < 5 {
        final_filter.extend_from_slice(&filter_keyring);
    }

    if block_nested_ns {
        log_info!("[SEC] --block-nested-namespaces: force blocking namespace syscalls.");
        final_filter.extend_from_slice(&filter_ns);
    }

    final_filter.extend_from_slice(&filter_allow);

    // 应用过滤器
    let prog = libc::sock_fprog {
        len: final_filter.len() as u16,
        filter: final_filter.as_ptr() as *mut libc::sock_filter,
    };

    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog, 0, 0) } < 0 {
        log_warn!("Failed to apply Seccomp filter: {}", io::Error::last_os_error());
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
