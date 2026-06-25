//! 常量定义 —— 对应原 asc.h 中的 #define 宏。
//!
//! 所有路径常量使用 `concat!` + `env!("CARGO_PKG_NAME")` 在编译期展开，
//! 与 CMake 生成的 version.h 中 `PROJECT_NAME` 行为一致。

/// 最低内核版本要求
pub const MIN_KERNEL_MAJOR: i32 = 4;
pub const MIN_KERNEL_MINOR: i32 = 9;

/// UUID 长度（32 个十六进制字符，无连字符）
pub const UUID_LEN: usize = 32;

/// 最大容器数量
pub const MAX_CONTAINERS: usize = 1024;

/// 停止超时（秒）
pub const STOP_TIMEOUT: i32 = 15;

/// PID 扫描重试次数
pub const PID_SCAN_RETRIES: i32 = 20;

/// PID 扫描间隔（微秒）—— 200ms
pub const PID_SCAN_DELAY_US: i32 = 200_000;

/// 重试延迟（微秒）—— 200ms
pub const RETRY_DELAY_US: i32 = 200_000;

/// 容器内重启的退出码
pub const REBOOT_EXIT: i32 = 249;

// ── 运行时路径（全部位于 /tmp/<项目名>，tmpfs 上，重启即消失）──

/// 项目名称，与 CMake 生成的 PROJECT_NAME 一致
pub const PROJECT_NAME: &str = env!("CARGO_PKG_NAME");

/// 运行时目录: /tmp/asc
pub const RUNTIME_DIR: &str = concat!("/tmp/", env!("CARGO_PKG_NAME"));

/// 锁文件子目录
pub const RUNTIME_LOCK_SUBDIR: &str = "lock";

/// 配置子目录
pub const RUNTIME_CONFIG_SUBDIR: &str = "config";

/// 日志子目录
pub const RUNTIME_LOGS_SUBDIR: &str = "logs";

/// 易失性子目录
pub const RUNTIME_VOLATILE_SUBDIR: &str = "volatile";

/// 挂载点子目录
pub const RUNTIME_MNT_SUBDIR: &str = "mnt";

/// 镜像挂载根目录: /mnt/asc
pub const IMG_MOUNT_ROOT: &str = concat!("/mnt/", env!("CARGO_PKG_NAME"));

/// 最大挂载尝试次数
pub const MAX_MOUNT_TRIES: usize = 1024;

/// 初始 bind mount 容量
pub const BIND_INITIAL_CAP: usize = 4;

/// 默认 init 路径
pub const DEFAULT_INIT: &str = "/sbin/init";

/// Android tmpfs SELinux 上下文
pub const ANDROID_TMPFS_CONTEXT: &str = "u:object_r:tmpfs:s0";

// ── 通用路径和模式 ──

/// /proc/<pid>/root 格式字符串（用于 C FFI）
pub const PROC_ROOT_FMT: &str = "/proc/%d/root";

/// /proc/<pid>/cmdline 格式字符串
pub const PROC_CMDLINE_FMT: &str = "/proc/%d/cmdline";

/// /proc/<pid>/status 格式字符串
pub const PROC_STATUS_FMT: &str = "/proc/%d/status";

/// /proc/self/mountinfo
pub const PROC_MOUNTINFO: &str = "/proc/self/mountinfo";

/// /etc/os-release
pub const OS_RELEASE: &str = "/etc/os-release";

/// Android 内核固件路径参数
pub const FW_PATH_FILE: &str = "/sys/module/firmware_class/parameters/path";

/// 容器 fork 标记文件: /run/asc
pub const FORK_MARKER: &str = concat!("/run/", env!("CARGO_PKG_NAME"));

// ── 安全加固常量 ──

/// 默认 TTY 组 ID
pub const DEFAULT_TTY_GID: u32 = 5;

/// 最大跟踪条目数
pub const MAX_TRACKED_ENTRIES: usize = 512;

// ── 文件扩展名 ──

/// 锁文件扩展名
pub const EXT_LOCK: &str = ".lock";

// ── Android 内核 fw_path_para 缓冲区大小（含 NUL 终止符）──

pub const FW_PATH_BUF_SIZE: usize = 256;
