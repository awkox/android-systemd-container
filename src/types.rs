//! 数据结构定义 —— 对应原 asc.h 中的 enum / struct / typedef。
//!
//! 在 C 代码中部分字段使用固定长度 char 数组（如 `char[PATH_MAX]`），
//! 在 Rust 中统一替换为 `PathBuf` / `String`，避免缓冲区溢出，
//! 同时保留在序列化/FFI 边界处的长度校验逻辑。

use std::path::PathBuf;

// ── 网络模式 ──

/// 容器网络模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    /// 共享宿主机网络命名空间（默认）
    Host = 0,
    /// 隔离网络命名空间，仅 loopback
    None = 1,
}

// ── 特权标志位 ──

/// 不禁用 jail masks（/proc、/sys）
pub const PRIV_NOMASK: u32 = 1 << 0;
/// 不丢弃 capabilities
pub const PRIV_NOCAPS: u32 = 1 << 1;
/// 仅使用最小 seccomp 过滤器
pub const PRIV_NOSEC: u32 = 1 << 2;
/// root 传播使用 MS_SHARED
pub const PRIV_SHARED: u32 = 1 << 3;
/// 不过滤设备节点（除 PTY 外）
pub const PRIV_UNFILTERED: u32 = 1 << 4;
/// 以上全部特权
pub const PRIV_FULL: u32 = 0xFF;

// ── Bind mount 条目 ──

/// 单个 bind mount 配置
#[derive(Debug, Clone)]
pub struct BindMount {
    /// 宿主机源路径
    pub src: PathBuf,
    /// 容器内目标路径
    pub dest: PathBuf,
    /// 是否只读挂载
    pub ro: bool,
}

// ── 配置行链表节点 ──

/// 保留的未知配置行（Android 元数据）
#[derive(Debug, Clone)]
pub struct ConfigLine {
    /// 配置行内容（原 C 中为 `char[2048]`）
    pub line: String,
    /// 链表下一个节点
    pub next: Option<Box<ConfigLine>>,
}

// ── 终端/TTY 信息 ──

/// 每个分配的 PTY 的信息
#[derive(Debug, Clone)]
pub struct TtyInfo {
    /// master fd（保持在父进程/监控进程中）
    pub master: i32,
    /// slave fd（bind mount 到容器内）
    pub slave: i32,
    /// slave 设备路径（如 /dev/pts/3）
    pub name: PathBuf,
}

impl Default for TtyInfo {
    fn default() -> Self {
        Self {
            master: -1,
            slave: -1,
            name: PathBuf::new(),
        }
    }
}

// ── 完整容器配置 ──

/// 容器配置 —— 替换原 C 中的所有全局变量
///
/// 注意：原 C 中部分字段使用 `char[PATH_MAX]` 等固定缓冲区，
/// Rust 版本使用 `PathBuf` 以消除缓冲区溢出风险。
/// 与 C 代码对接时请注意路径长度的隐式约束。
#[derive(Debug, Clone)]
pub struct Config {
    // ── 路径 ──
    /// --rootfs-img= 原始 rootfs 镜像路径
    pub rootfs_img_path: PathBuf,
    /// --name= 容器名称（必填，原 C 限制 256 字节）
    pub container_name: String,
    /// --net=host|none 网络模式
    pub net_mode: NetMode,

    // ── UUID（用于 PID 发现）──
    /// 32 个十六进制字符的 UUID
    pub uuid: String,

    // ── 标志 ──
    /// --foreground 前台模式
    pub foreground: bool,
    /// --hw-access 硬件访问
    pub hw_access: bool,
    /// --gpu 将 GPU 节点镜像到隔离的 tmpfs /dev
    pub gpu_mode: bool,
    /// --volatile 易失模式
    pub volatile_mode: bool,
    /// 是否处于重启循环中
    pub reboot_cycle: bool,
    /// --force-cgroupv1 强制使用 cgroup v1
    pub force_cgroupv1: bool,
    /// --block-nested-namespaces 阻止嵌套命名空间创建
    pub block_nested_ns: bool,
    /// --privileged 特权位掩码
    pub privileged_mask: u32,
    /// --format 机器可解析输出 (KEY=VALUE)
    pub format_output: bool,
    /// argv[0] 用于日志
    pub prog_name: String,

    // ── 运行时状态 ──
    /// 临时 overlay 目录
    pub volatile_dir: PathBuf,
    /// 容器 PID 1（宿主机视角）
    pub container_pid: Option<libc::pid_t>,
    /// 中间 fork 进程 PID
    pub intermediate_pid: Option<libc::pid_t>,
    /// .img 镜像挂载点
    pub img_mount_point: PathBuf,
    /// --init=PATH 覆盖（默认 /sbin/init）
    pub custom_init: PathBuf,

    // ── 自定义 bind mount（动态数组）──
    pub binds: Vec<BindMount>,

    // ── 配置持久化 ──
    pub config_file: PathBuf,
    pub config_file_specified: bool,
    pub config_file_existed: bool,

    // ── 终端（console + ttys）──
    pub console: TtyInfo,

    // ── 未知配置行（保留 Android 元数据）──
    pub unknown_lines: Vec<String>,

    // ── 资源限制（0 = 无限制）──
    /// 内存限制（字节）
    pub memory_limit: Option<i64>,
    /// CPU 配额（微秒/周期）
    pub cpu_quota: Option<i64>,
    /// CPU 周期（微秒，默认 100000）
    pub cpu_period: Option<i64>,
    /// PID 数量限制
    pub pids_limit: Option<i64>,

    // ── 资源虚拟化 ──
    /// 容器启动时间（CLOCK_MONOTONIC）
    pub start_time: libc::timespec,
    /// PID 命名空间 inode（用于 PID 回收防护）
    pub ns_inode: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rootfs_img_path: PathBuf::new(),
            container_name: String::new(),
            net_mode: NetMode::Host,
            uuid: String::new(),
            foreground: false,
            hw_access: false,
            gpu_mode: false,
            volatile_mode: false,
            reboot_cycle: false,
            force_cgroupv1: false,
            block_nested_ns: false,
            privileged_mask: 0,
            format_output: false,
            prog_name: String::new(),
            volatile_dir: PathBuf::new(),
            container_pid: None,
            intermediate_pid: None,
            img_mount_point: PathBuf::new(),
            custom_init: PathBuf::new(),
            binds: Vec::new(),
            config_file: PathBuf::new(),
            config_file_specified: false,
            config_file_existed: false,
            console: TtyInfo::default(),
            unknown_lines: Vec::new(),
            memory_limit: None,
            cpu_quota: None,
            cpu_period: None,
            pids_limit: None,
            start_time: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            ns_inode: 0,
        }
    }
}

// ── 日志全局状态 ──

/// 日志全局状态结构体
///
/// 对应原 C 中的三个全局变量:
/// - `extern int log_silent;`
/// - `extern char log_container_name[256];`
/// - `extern int log_container_fd;`
#[derive(Debug)]
pub struct LogState {
    /// 静默模式（抑制非错误终端输出）
    pub silent: bool,
    /// 当前容器名称（用于日志文件命名）
    pub container_name: String,
    /// 容器日志文件描述符（-1 = 未打开）
    pub container_fd: i32,
}

impl Default for LogState {
    fn default() -> Self {
        Self {
            silent: false,
            container_name: String::new(),
            container_fd: -1,
        }
    }
}

// ── RTNETLINK 上下文（不透明类型） ──

/// 不透明的 RTNETLINK 上下文（定义在 netlink.c / netlink.rs 中）
pub struct NlCtx {
    pub fd: i32,
    pub seq: u32,
    pub pid: u32,
}
