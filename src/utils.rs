//! 工具函数 —— 对应原 utils.c。
//!
//! 包含字符串处理、路径解析、文件 I/O、UUID 生成、PID 扫描、/proc 操作、
//! 内核固件路径管理、命令执行、系统探测、日志引擎、容器运行时统计、
//! bind mount 排序、名称校验、大小解析、OOM 防护等功能。
//!
//! # 与 C 代码的主要差异
//!
//! - 路径使用 `PathBuf` / `&Path` 替代固定大小的 `char[PATH_MAX]`
//! - 动态数组使用 `Vec<T>` 替代 `malloc`+`realloc`
//! - 错误处理使用 `io::Result<T>` 替代 -1 返回值
//! - 日志全局状态使用 `Mutex<LogState>` 确保线程安全
//! - 原始 fd 写入使用 `libc::write`（小段 `unsafe`）

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::constants;
use crate::types::{Config, LogState};

// ── 日志全局状态 ──

/// 全局日志状态（对应 C 中的 `log_silent`, `log_container_name`, `log_container_fd`）
static LOG_STATE: Mutex<LogState> = Mutex::new(LogState {
    silent: false,
    container_name: String::new(),
    container_fd: -1,
});

// ── 来自其它模块的真实实现（按依赖关系延迟解析，Rust 中跨模块互相调用不存在
//    C 头文件式的"循环包含"问题，因此可以放心直接引用）──

/// 返回运行时目录路径（来自 pid.c，简单常数返回）
pub fn get_runtime_dir() -> &'static str {
    constants::RUNTIME_DIR
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. 字符串处理
// ══════════════════════════════════════════════════════════════════════════════

/// 安全字符串复制 —— 防止缓冲区溢出。
///
/// 对应 C 的 `safe_strncpy()`。
/// 在 Rust 中通常建议直接使用 `clone()` 或 `to_string()`，
/// 此函数保留以兼容需要固定缓冲区的 FFI 场景。
pub fn safe_strncpy(dst: &mut [u8], src: &[u8]) {
    if dst.is_empty() {
        return;
    }
    if src.is_empty() {
        dst[0] = 0;
        return;
    }

    let copy_len = src.len().min(dst.len() - 1);

    // 注意：C 版本会在截断时发出 log_warn，但由于 log_warn 宏依赖
    // 此模块内的 log_internal（循环依赖），这里不打印日志。
    // 调用方如需截断警告可自行检查。
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    // 确保 NUL 终止（兼容 C FFI）
    if copy_len < dst.len() {
        dst[copy_len] = 0;
    }
    // 如果 src 恰好填满整个 dst，最后位置应被 NUL 覆盖
    if copy_len == dst.len() {
        dst[dst.len() - 1] = 0;
    }
}

/// 镜像 Android App 中 `sanitizeContainerName()` 的行为：
/// 将空格替换为连字符，保证目录名一致性。
pub fn sanitize_container_name(name: &str) -> String {
    name.chars().map(|c| if c == ' ' { '-' } else { c }).collect()
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. 路径解析
// ══════════════════════════════════════════════════════════════════════════════

/// 解析相对路径为绝对路径。
///
/// 策略（与 C 版本一致）：
/// 1. 展开 `~/` → `$HOME/`
/// 2. 如果已是绝对路径 `/...`，返回去尾斜杠的副本
/// 3. 调用 `realpath(3)` 尝试规范化（处理 `..`、符号链接等），仅对已存在的路径有效
/// 4. 对尚不存在的路径，回退到 cwd 拼接（去除前导 `./`）
pub fn resolve_path_arg(path: &str) -> io::Result<PathBuf> {
    if path.is_empty() {
        return Ok(PathBuf::new());
    }

    let p: String;

    // 展开 ~/
    if path.starts_with("~/") || path == "~" {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let rest = &path[1..]; // 去掉 ~，保留 / 或空
            p = format!("{}{}", home, rest);
        } else {
            p = path.to_string();
        }
    } else {
        p = path.to_string();
    }

    // 如果已是绝对路径，直接去尾斜杠后返回
    if p.starts_with('/') {
        let mut res = p;
        // 去掉末尾多余的 `/`（保留单独的 `/`）
        while res.len() > 1 && res.ends_with('/') {
            res.pop();
        }
        return Ok(PathBuf::from(res));
    }

    // 快速路径：realpath(3) 处理已存在的路径
    let resolved = std::fs::canonicalize(&p);
    if let Ok(canon) = resolved {
        return Ok(canon);
    }

    // 路径尚不存在 —— 从当前 CWD 拼接
    // 去除前导 `./` 噪音
    let suffix = p.strip_prefix("./").unwrap_or(&p);

    if suffix.is_empty() {
        // 输入纯 "./" → 解析为 CWD
        return std::env::current_dir();
    }

    let cwd = std::env::current_dir()?;
    let mut out = cwd;
    out.push(suffix);
    Ok(out)
}

/// 将 argv 中需要路径解析的选项参数原地解析为绝对路径。
///
/// 对应 C 的 `resolve_argv_paths()`。
/// 在 Rust 中，我们不直接修改 argv，而是返回修改后的向量。
/// 仅处理 `--config` / `-C` 选项（与 C 的 `path_opts[]` 表一致）。
pub fn resolve_argv_paths(args: &[String]) -> Vec<String> {
    let path_opts: &[&str] = &["--config", "-C"];
    let mut result = args.to_vec();
    let mut i = 0;

    while i < result.len() {
        let arg = &result[i];
        if arg.is_empty() || !arg.starts_with('-') {
            i += 1;
            continue;
        }

        for opt in path_opts {
            let olen = opt.len();

            // "--opt=VALUE" 形式
            if arg.len() > olen && arg[..olen] == **opt && arg.as_bytes()[olen] == b'=' {
                let val = &arg[olen + 1..];
                if !val.is_empty() && !val.starts_with('/') {
                    if let Ok(resolved) = resolve_path_arg(val) {
                        result[i] = format!("{}={}", opt, resolved.display());
                    }
                }
                break;
            }

            // "--opt VALUE" 形式（值在下一个元素）
            if arg.as_str() == *opt && i + 1 < result.len() {
                let val = &result[i + 1];
                if !val.is_empty() && !val.starts_with('/') {
                    if let Ok(resolved) = resolve_path_arg(val) {
                        result[i + 1] = resolved.display().to_string();
                    }
                }
                break;
            }
        }
        i += 1;
    }
    result
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. 路径工具
// ══════════════════════════════════════════════════════════════════════════════

/// 判断路径是否为 ramfs 或 tmpfs。
///
/// 使用 `statfs(2)` 检查文件系统类型。
/// 仅在 Linux 上有效，在其他平台上（无 RAMFS_MAGIC/TMPFS_MAGIC）返回 false。
pub fn is_ramfs(path: &Path) -> bool {
    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statfs(c_path.as_ptr(), &mut sfs) };
    if ret < 0 {
        return false;
    }

    // RAMFS_MAGIC = 0x858458f6 (defined in <linux/magic.h>, not exported by libc crate)
    // TMPFS_MAGIC = 0x01021994
    const RAMFS_MAGIC: libc::c_long = 0x858458f6;
    sfs.f_type == RAMFS_MAGIC || sfs.f_type == libc::TMPFS_MAGIC
}

/// 判断 `child` 路径是否在 `parent` 目录树之下。
///
/// 先对两者调用 `resolve_path_arg` 进行规范化，
/// 然后检查 child 是否以 parent 路径为前缀。
/// 特殊处理根目录 `/`（所有路径都在其之下）。
pub fn is_subpath(parent: &str, child: &str) -> bool {
    let real_parent = resolve_path_arg(parent).unwrap_or_else(|_| PathBuf::new());
    let real_child = resolve_path_arg(child).unwrap_or_else(|_| PathBuf::new());

    if real_parent.as_os_str().is_empty() || real_child.as_os_str().is_empty() {
        return false;
    }

    // 根目录特殊处理
    if real_parent == Path::new("/") {
        return true;
    }

    // child 必须以 parent 为前缀，且紧随的字符是 '\0' 或 '/'
    real_child.starts_with(&real_parent)
        && (real_child.as_os_str().len() == real_parent.as_os_str().len()
            || real_child
                .as_os_str()
                .as_bytes()
                .get(real_parent.as_os_str().len())
                == Some(&b'/'))
}

/// 递归创建目录（类似 `mkdir -p`）。
///
/// 使用标准库的 `fs::create_dir_all`，同时返回 io::Result。
/// 注意：原 C 版本使用自定义 mkdir 循环并忽略 EEXIST 错误；
/// Rust 的 `create_dir_all` 已经内置了此行为。
pub fn mkdir_p(path: &Path, mode: u32) -> io::Result<()> {
    // create_dir_all 不支持自定义 mode 位！
    // 所以我们先在父级使用默认模式创建，再在最终目录上设置 mode。
    // 然而由于 Unix 权限模型的限制，自定义 mode 需要直接使用 libc::mkdir。
    // 这里优先使用 libc 以获得与 C 代码完全一致的 mode 行为。

    let path_bytes = path.as_os_str().as_bytes();
    // 需要 NUL 终止的 C 字符串
    let mut tmp = Vec::with_capacity(path_bytes.len() + 1);
    tmp.extend_from_slice(path_bytes);
    tmp.push(0);

    let mut buf = tmp.clone();

    // 去掉末尾的 '/'
    let mut end = buf.len() - 1; // -1 for NUL
    if end > 0 && buf[end - 1] == b'/' {
        end -= 1;
        buf[end] = 0;
    }

    // 逐个路径组件创建（跳过根 '/'）
    for pos in 1..end {
        if buf[pos] == b'/' {
            buf[pos] = 0;
            let ret = unsafe { libc::mkdir(buf.as_ptr() as *const libc::c_char, mode as libc::mode_t) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(err);
                }
            }
            buf[pos] = b'/';
        }
    }
    // 最终目录
    let ret = unsafe { libc::mkdir(buf.as_ptr() as *const libc::c_char, mode as libc::mode_t) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }
    Ok(())
}

/// 检查路径的任何前缀组件是否为符号链接。
///
/// 使用 `lstat(2)` 遍历每个 `/` 分隔的路径前缀。
/// `lstat` 不会跟随最终组件的符号链接，因此可以检测到任意层级的符号链接。
///
/// 返回 `true` 表示路径中存在符号链接组件。
pub fn path_has_symlink(path: &Path) -> bool {
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty() {
        return false;
    }

    // 复制一份用于逐步截断检查
    let mut tmp: Vec<u8> = Vec::with_capacity(path_bytes.len() + 1);
    tmp.extend_from_slice(path_bytes);
    tmp.push(0);

    let len = tmp.len() - 1; // 不含 NUL
    if len == 0 {
        return false;
    }

    // 遍历每个 '/' 边界，用 lstat 检查前缀
    for pos in 1..len {
        if tmp[pos] == b'/' {
            tmp[pos] = 0;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::lstat(tmp.as_ptr() as *const libc::c_char, &mut st)
            };
            if ret == 0 {
                // S_ISLNK: (st.st_mode & S_IFMT) == S_IFLNK
                let is_lnk = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
                if is_lnk {
                    return true;
                }
            }
            tmp[pos] = b'/';
        }
    }

    // 检查完整路径
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret =
        unsafe { libc::lstat(tmp.as_ptr() as *const libc::c_char, &mut st) };
    if ret == 0 {
        let is_lnk = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        if is_lnk {
            return true;
        }
    }

    false
}

/// 递归删除目录及其内容。
///
/// 对应 C 中基于 `nftw(FTW_DEPTH | FTW_PHYS)` 的 `remove_recursive`。
/// Rust 标准库的 `fs::remove_dir_all` 提供等效功能。
pub fn remove_recursive(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)
    } else if path.exists() {
        fs::remove_file(path)
    } else {
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. 文件 I/O
// ══════════════════════════════════════════════════════════════════════════════

/// 将字符串内容写入文件（覆盖模式，权限 0644，O_CLOEXEC）。
pub fn write_file(path: &Path, content: &str) -> io::Result<()> {
    // 使用 OpenOptions 以匹配 C 的 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // O_CLOEXEC: 在 Linux 上使用自定义标志
    opts.custom_flags(libc::O_CLOEXEC);

    let mut file = opts.open(path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// 向原始 fd 写入全部数据，处理 EINTR 中断。
///
/// 对应 C 的 `write_all()`。
/// # Safety
/// `fd` 必须是有效的文件描述符。
/// 函数不获取 fd 所有权，不会关闭它。
pub unsafe fn write_all_raw(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let mut p = buf.as_ptr();
    let mut remaining: isize = buf.len() as isize; // 使用 isize 安全处理剩余字节

    while remaining > 0 {
        let w = unsafe {
            libc::write(
                fd,
                p as *const libc::c_void,
                remaining as usize,
            )
        };
        if w < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        // w >= 0，安全地从 isize 中减去
        remaining -= w as isize;
        p = unsafe { p.add(w as usize) };
    }
    Ok(buf.len())
}

/// 将字符串写入原始 fd（带 EINTR 处理）。
///
/// 用于日志引擎向预打开的文件描述符写入日志行。
fn write_str_to_fd(fd: RawFd, s: &str) -> io::Result<()> {
    // SAFETY: 调用方保证 fd 有效
    unsafe { write_all_raw(fd, s.as_bytes()) }?;
    Ok(())
}

/// 读取文件的全部文本内容，去除尾部换行符和回车符。
///
/// 对应 C 的 `read_file()`。返回去除尾部 `\n` / `\r` 后的字符串。
pub fn read_file(path: &Path) -> io::Result<String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_CLOEXEC);

    let mut file = opts.open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // 去除尾部换行符和回车符（与 C 行为一致）
    while content.ends_with('\n') || content.ends_with('\r') {
        content.pop();
    }

    Ok(content)
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. UUID 生成 —— 32 个十六进制字符
// ══════════════════════════════════════════════════════════════════════════════

/// 生成 32 个十六进制字符的 UUID（无连字符）。
///
/// 主路径：从 `/dev/urandom` 读取 16 字节随机数据。
/// 回退路径：使用基于时间戳、PID 和 PPID 种子的 `rand()`。
pub fn generate_uuid() -> io::Result<String> {
    // 主路径：/dev/urandom
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut raw = [0u8; 16]; // UUID_LEN / 2 = 16
        match f.read_exact(&mut raw) {
            Ok(()) => {
                let uuid: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
                return Ok(uuid);
            }
            Err(_) => {
                // 回退到 rand()
            }
        }
    }

    // 回退路径：seeded rand()
    use std::sync::Once;
    static SEED_INIT: Once = Once::new();

    SEED_INIT.call_once(|| {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        let seed = (ts.tv_nsec as u32)
            ^ (ts.tv_sec as u32)
            ^ (unsafe { libc::getpid() } as u32)
            ^ (unsafe { libc::getppid() } as u32);
        unsafe {
            libc::srand(seed);
        }
    });

    let mut raw = [0u8; 16];
    for byte in raw.iter_mut() {
        // rand() 返回 0..RAND_MAX，取低 8 位
        *byte = (unsafe { libc::rand() } & 0xFF) as u8;
    }

    let uuid: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(uuid)
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. PID 收集 —— 读取 /proc 的数字条目
// ══════════════════════════════════════════════════════════════════════════════

/// 收集 `/proc` 中所有数字目录名对应的 PID。
///
/// 对应 C 的 `collect_pids()`。
/// 不信任 `d_type`（某些文件系统返回 DT_UNKNOWN）。
/// 使用 `strtol` 验证纯数字条目。
pub fn collect_pids() -> io::Result<Vec<libc::pid_t>> {
    let mut pids: Vec<libc::pid_t> = Vec::with_capacity(256);

    let proc_dir = fs::read_dir("/proc")?;
    for entry in proc_dir {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // 必须是纯正数
        if let Ok(val) = name_str.parse::<i64>() {
            if val > 0 {
                pids.push(val as libc::pid_t);
            }
        }
    }

    Ok(pids)
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. /proc 路径工具
// ══════════════════════════════════════════════════════════════════════════════

/// 构造 `/proc/<pid>/root[<suffix>]` 路径。
///
/// 返回格式化后的路径字符串，足够用于 `readlink` 或 `open`。
pub fn build_proc_root_path(pid: libc::pid_t, suffix: Option<&str>) -> String {
    if let Some(s) = suffix {
        if !s.is_empty() {
            return format!("/proc/{}/root{}", pid, s);
        }
    }
    format!("/proc/{}/root", pid)
}

/// 解析容器 rootfs 中的 `/etc/os-release` 文件。
///
/// 返回 `(ID, VERSION_ID)` 元组。
/// 如果 VERSION_ID 不存在，第二个元素为 `None`。
/// 默认 ID 为 "linux"（与 C 代码一致）。
pub fn parse_os_release(rootfs_path: &Path) -> io::Result<(String, Option<String>)> {
    let mut path = rootfs_path.to_path_buf();
    // 去除 rootfs_path 中的 "%.4000s" 格式化限制，
    // 在 Rust 中路径没有隐式截断。
    path.push(constants::OS_RELEASE.trim_start_matches('/'));

    let content = read_file(&path)?;

    let id = parse_os_release_key(&content, "ID=").unwrap_or_else(|| "linux".to_string());
    let version_id = parse_os_release_key(&content, "VERSION_ID=");

    Ok((id, version_id))
}

/// 从 os-release 内容中提取指定键的值。
fn parse_os_release_key(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(val) = line.strip_prefix(key) {
            // 去除开头和结尾的引号
            let val = val.trim_start_matches('"').trim_end_matches('"');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// 在文件中搜索模式（简单子串搜索）。
///
/// 返回 `true` 如果文件包含该模式，`false` 否则。
/// 读取失败时返回 `Err`。
pub fn grep_file(path: &Path, pattern: &str) -> io::Result<bool> {
    let content = read_file(path)?;
    Ok(content.contains(pattern))
}

/// 读取 `/proc/<pid>/environ` 中指定键的值。
///
/// 进程环境变量以 `KEY=VALUE\0` 的 NUL 分隔格式存储。
/// 返回 `Some(value)` 如果找到该键，`None` 如果未找到。
pub fn read_proc_environ(pid: libc::pid_t, key: &str) -> io::Result<Option<String>> {
    if key.is_empty() || pid <= 0 {
        return Ok(None);
    }

    let path = format!("/proc/{}/environ", pid);

    // 读取原始字节（环境变量可能包含非 UTF-8 数据）
    let raw = fs::read(&path)?;

    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();

    // 遍历 NUL 分隔的条目
    let mut pos = 0;
    while pos < raw.len() {
        let end = raw[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| pos + p)
            .unwrap_or(raw.len());

        let entry = &raw[pos..end];
        pos = end + 1; // 跳过 NUL

        // 检查是否以 "KEY=" 开头
        if entry.len() > key_len
            && entry[..key_len] == key_bytes[..]
            && entry[key_len] == b'=' {
            // 提取值（= 之后到条目结束）
            let value_bytes = &entry[key_len + 1..];
            let value = String::from_utf8_lossy(value_bytes).to_string();
            return Ok(Some(value));
        }
    }

    Ok(None)
}

/// 安全地打开 `/proc/<pid>/root/<subpath>`，防止符号链接注入。
///
/// `open("/proc/pid/root/sub/dir/file", O_NOFOLLOW)` 仅保护**最终**组件。
/// 内核会静默跟随 `sub` 或 `dir` 级别的符号链接。
/// 此函数使用 `openat(O_NOFOLLOW)` 逐组件遍历，任何中间符号链接都会导致失败。
///
/// `/proc/<pid>/root` 本身是魔术符号链接，**必须**被跟随（不能用 O_NOFOLLOW）。
pub fn safe_openat_proc(
    pid: libc::pid_t,
    subpath: &str,
    flags: i32,
    mode: u32,
) -> io::Result<RawFd> {
    if pid <= 0 || subpath.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    // 进入容器 root。O_PATH | O_DIRECTORY，跟随 /proc/<pid>/root 魔术符号链接
    let root_path = CString::new(format!("/proc/{}/root", pid))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let dirfd = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 逐组件遍历，使用 O_NOFOLLOW 防止符号链接攻击
    let components: Vec<&str> = subpath
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if components.is_empty() {
        return Ok(dirfd);
    }

    let mut current_fd = dirfd;
    let last_idx = components.len() - 1;

    for (i, comp) in components.iter().enumerate() {
        let c_comp = CString::new(*comp)
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        let next_fd = if i == last_idx {
            // 最后一个组件：使用调用方请求的 flags + O_NOFOLLOW + O_CLOEXEC
            unsafe {
                libc::openat(
                    current_fd,
                    c_comp.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    mode as libc::mode_t,
                )
            }
        } else {
            // 中间组件：O_PATH | O_NOFOLLOW | O_DIRECTORY
            unsafe {
                libc::openat(
                    current_fd,
                    c_comp.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                )
            }
        };

        // 关闭上一个 fd（除了原始 dirfd）
        unsafe { libc::close(current_fd) };

        if next_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        current_fd = next_fd;
    }

    Ok(current_fd)
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. 内核固件搜索路径管理
// ══════════════════════════════════════════════════════════════════════════════

/// 从逗号分隔列表中按完整 token 匹配移除指定路径。
///
/// 仅在 `--hw-access` 激活且 rootfs 中存在 `/lib/firmware` 时调用。
/// Android 内核限制了 256 字节的 fw_path_para 缓冲区。
///
/// 返回 (remaining_len, rebuilt_string)。
/// 如果 remaining_len == 0，表示该路径是唯一条目，不写入（内核不允许完全清空）。
fn fw_remove_token(buf: &str, token: &str, out: &mut String) -> usize {
    out.clear();

    let token_len = token.len();
    let mut first = true;

    for seg in buf.split(',') {
        if seg.is_empty() {
            continue;
        }
        if seg.len() == token_len && seg == token {
            // 匹配到我们的 token —— 跳过
            continue;
        }
        // 不是我们的 token —— 保留
        if !first {
            out.push(',');
        }
        out.push_str(seg);
        first = false;
    }

    out.len()
}

/// 向 Android 内核固件搜索路径列表中添加路径。
///
/// 仅当 `/lib/firmware` 存在于 rootfs 中时调用。
/// 在桌面 Linux 上是空操作（sysfs 节点存在但逻辑适用）。
pub fn firmware_path_add(fw_path: &Path) -> io::Result<()> {
    // 如果 fw_path 下的 /lib/firmware 不存在，静默退出
    if !fw_path.exists() {
        return Ok(());
    }

    let fw_path_str = fw_path.to_string_lossy();

    // 读取当前逗号分隔路径列表
    let current = read_file(Path::new(constants::FW_PATH_FILE)).unwrap_or_default();

    // 幂等性：如果已作为完整 token 存在则跳过
    let fw_len = fw_path_str.len();
    for seg in current.split(',') {
        if seg.len() == fw_len && seg == fw_path_str.as_ref() {
            return Ok(()); // 已存在
        }
    }

    // 构造 "fw_path,existing"（前缀优先，容器固件优先于 OEM 默认值）
    let new_path = if current.is_empty() {
        fw_path_str.to_string()
    } else {
        let mut s = String::with_capacity(fw_len + 1 + current.len());
        s.push_str(&fw_path_str);
        s.push(',');
        s.push_str(&current);
        s
    };

    // Android 内核 fw_path_para 限制为 255 字符（+ NUL）
    if new_path.len() >= constants::FW_PATH_BUF_SIZE {
        // 对应 log_warn!("[FW] firmware path too long to prepend ...")
        eprintln!(
            "[FW] firmware path too long to prepend '{}' - skipping",
            fw_path_str
        );
        return Ok(());
    }

    // 写入 sysfs 节点
    write_file(Path::new(constants::FW_PATH_FILE), &new_path)
}

/// 从 Android 内核固件搜索路径列表中移除路径。
///
/// 如果该路径是唯一的条目，跳过移除（内核不允许完全清空）。
pub fn firmware_path_remove(fw_path: &Path) -> io::Result<()> {
    let fw_path_str = fw_path.to_string_lossy();

    let current = match read_file(Path::new(constants::FW_PATH_FILE)) {
        Ok(c) => c,
        Err(_) => return Ok(()), // 读取失败，静默退出
    };

    let mut new_path = String::with_capacity(constants::FW_PATH_BUF_SIZE);
    let new_len = fw_remove_token(&current, &fw_path_str, &mut new_path);

    if new_len == 0 {
        // 我们的路径是唯一条目。Android 内核不允许完全清空 —— 写入空字符串是空操作。
        return Ok(());
    }

    write_file(Path::new(constants::FW_PATH_FILE), &new_path)
}

// ══════════════════════════════════════════════════════════════════════════════
// 9. 命令执行（fork + execvp）
// ══════════════════════════════════════════════════════════════════════════════

/// 内部：fork + execvp，可选静默模式。
unsafe fn internal_run(argv: &[CString], quiet: bool) -> io::Result<i32> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // 子进程
        if quiet {
            let devnull = unsafe { libc::open(b"/dev/null\0" as *const u8 as *const libc::c_char, libc::O_RDWR) };
            if devnull >= 0 {
                unsafe {
                    libc::dup2(devnull, libc::STDOUT_FILENO);
                    libc::dup2(devnull, libc::STDERR_FILENO);
                    libc::close(devnull);
                }
            }
        }

        // 构造 char* const[] 参数数组
        let mut c_args: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        c_args.push(std::ptr::null());

        unsafe {
            libc::execvp(c_args[0], c_args.as_ptr());
        }
        // execvp 失败
        unsafe { libc::_exit(127) };
    }

    // 父进程：等待子进程
    let mut status: libc::c_int = 0;
    let wret = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wret < 0 {
        return Err(io::Error::last_os_error());
    }

    // 检查子进程是否正常退出
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        // 被信号杀死等
        Err(io::Error::other("command terminated abnormally"))
    }
}

/// 静默执行外部命令（stdout/stderr 重定向到 /dev/null）。
///
/// 对应 C 的 `run_command_quiet()`。
/// # Safety
/// 调用 `fork()` 创建子进程。
pub fn run_command_quiet(argv: &[String]) -> io::Result<i32> {
    let c_args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_default())
        .collect();
    unsafe { internal_run(&c_args, true) }
}

// ══════════════════════════════════════════════════════════════════════════════
// 10. 系统工具
// ══════════════════════════════════════════════════════════════════════════════

/// 获取内核版本号（主版本号和次版本号）。
///
/// 通过 `uname(2)` 获取并解析 `release` 字段（如 "5.15.0"）。
pub fn get_kernel_version() -> io::Result<(i32, i32)> {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::uname(&mut uts) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // 将 C 字符串转换为 Rust 字符串
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .to_string();

    // 解析 "major.minor..." 格式
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected uname release format: {}", release),
        ));
    }

    let major: i32 = parts[0]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid major version"))?;
    let minor: i32 = parts[1]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid minor version"))?;

    Ok((major, minor))
}

/// 日志文件轮转 —— 当文件超过 max_size 时重命名为 .old。
pub fn rotate_log(path: &Path, max_size: u64) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() >= max_size {
            let old_path = path.with_extension("old");
            // 如果目标已存在，先删除
            if old_path.exists() {
                let _ = fs::remove_file(&old_path);
            }
            fs::rename(path, &old_path)?;
        }
    }
    Ok(())
}

/// 向原始 fd 写入格式化字符串（等效于 `dprintf`）。
///
/// 用于预打开的日志文件描述符（O_APPEND 使小消息的写入是原子的）。
fn dprintf(fd: RawFd, msg: &str) {
    if fd < 0 {
        return;
    }
    // 尝试写入，静默忽略错误（与 C 的 best-effort 行为一致）
    let _ = write_str_to_fd(fd, msg);
}

/// 核心日志写入函数 —— 统一处理文件日志和终端输出的路由。
///
/// 对应 C 的 `write_to_log_file()`。
fn write_to_log_file(name: &str, component: &str, raw_msg: &str, pre_opened_fd: i32) {
    if name.is_empty() {
        return;
    }

    // 获取时间戳
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }

    let secs = ts.tv_sec as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }

    let ms = ts.tv_nsec / 1_000_000; // 纳秒转毫秒

    let line = format!(
        "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}] [{}] {}\n",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        ms,
        component,
        raw_msg
    );

    if pre_opened_fd >= 0 {
        // 预打开的 FD 路径：在 pivot_root / mount namespace 变更后仍然有效
        // 就地轮转：当超过 2MB 时截断（rename 不可行，因为 FD 跟随 inode 而非路径）

        // 检查文件大小并轮转
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(pre_opened_fd, &mut st) } == 0 {
            // 2 * 1024 * 1024 = 2097152
            if (st.st_size as u64) >= 2 * 1024 * 1024 {
                unsafe {
                    libc::ftruncate(pre_opened_fd, 0);
                    libc::lseek(pre_opened_fd, 0, libc::SEEK_SET);
                }
            }
        }

        dprintf(pre_opened_fd, &line);
        return;
    }

    // 回退路径：按路径打开（pre-pivot、监控进程等）
    let safe_name = sanitize_container_name(name);
    let log_dir = format!(
        "{}/{}/{}",
        get_runtime_dir(),
        constants::RUNTIME_LOGS_SUBDIR,
        safe_name
    );
    let _ = mkdir_p(Path::new(&log_dir), 0o755);

    let log_path = format!("{}/log", log_dir);
    let log_path = Path::new(&log_path);
    let _ = rotate_log(log_path, 2 * 1024 * 1024);

    // 使用 "ae" 模式：追加 + close-on-exec
    if let Ok(mut f) = OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(log_path) {
        let _ = f.write_all(line.as_bytes());
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 11. 日志引擎
// ══════════════════════════════════════════════════════════════════════════════

/// 核心日志函数 —— 所有 log_info!/log_warn!/log_error! 宏的后端。
///
/// 同时写入文件日志和终端（受 `log_silent` 标志控制）。
/// 终端输出会过滤 `[DEBUG]`、`[CGROUP]`、`[VIRT]` 等内部前缀。
pub fn log_internal(prefix: &str, is_err: bool, args: fmt::Arguments) {
    let raw_msg = format!("{}", args);

    // 获取日志状态
    let state = LOG_STATE.lock().unwrap();

    // 始终写入文件日志（如果设置了容器名称）
    if !state.container_name.is_empty() {
        write_to_log_file(&state.container_name, "main", &raw_msg, state.container_fd);
    }

    // 判断是否打印到终端
    if state.silent && !is_err {
        return;
    }

    // 释放锁（在 I/O 之前释放以避免长时间持锁）
    drop(state);

    // 过滤内部调试/信息前缀（非错误级别）
    if !is_err {
        let filtered_prefixes = [
            "[DEBUG]", "[CGROUP]", "[VIRT]", "[IPT]", "[NET]", "[SEC]", "[GPU]",
            "[FW]", "[DHCP]", "[VirGL]", "[PulseAudio]", "[X11]",
        ];
        for prefix_pattern in &filtered_prefixes {
            if raw_msg.starts_with(prefix_pattern) {
                return;
            }
        }
    }

    let out: Box<dyn Write> = if is_err {
        Box::new(io::stderr())
    } else {
        Box::new(io::stdout())
    };

    // 获取可变的 out reference
    let mut out = out;
    let _ = writeln!(
        out,
        "[{}] {}\r",
        prefix, raw_msg
    );
    let _ = out.flush();
}

/// 致命错误日志 —— 打印后退出进程。
///
/// 对应 C 的 `die_internal()`。
pub fn die_internal(args: fmt::Arguments) {
    let raw_msg = format!("{}", args);

    // 写入文件日志（如果有容器上下文）
    let state = LOG_STATE.lock().unwrap();
    if !state.container_name.is_empty() {
        write_to_log_file(&state.container_name, "fatal", &raw_msg, state.container_fd);
    }
    drop(state);

    eprintln!("[-] {}\r", raw_msg);
    std::process::exit(libc::EXIT_FAILURE);
}

/// 写入监控调试日志。
///
/// 对应 C 的 `write_monitor_debug_log()`。
pub fn write_monitor_debug_log(name: &str, args: fmt::Arguments) {
    if name.is_empty() {
        return;
    }
    let raw_msg = format!("{}", args);
    write_to_log_file(name, "monitor", &raw_msg, -1);
}

// ══════════════════════════════════════════════════════════════════════════════
// 日志宏
// ══════════════════════════════════════════════════════════════════════════════

/// 信息级别日志（终端 `[+]`，写入文件日志）。
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::utils::log_internal(
            "+",
            false,
            format_args!($($arg)*),
        )
    };
}

/// 警告级别日志（终端 `[!]`，写入文件日志）。
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::utils::log_internal(
            "!",
            true,
            format_args!($($arg)*),
        )
    };
}

/// 错误级别日志（终端 `[-]`，写入文件日志）。
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::utils::log_internal(
            "-",
            true,
            format_args!($($arg)*),
        )
    };
}

/// 致命错误日志 —— 打印后 `exit(EXIT_FAILURE)`。
#[macro_export]
macro_rules! log_die {
    ($($arg:tt)*) => {
        $crate::utils::die_internal(format_args!($($arg)*))
    };
}

// ── 日志状态管理 ──

/// 设置静默模式（抑制非错误终端输出）。
pub fn set_log_silent(silent: bool) {
    if let Ok(mut state) = LOG_STATE.lock() {
        state.silent = silent;
    }
}

/// 设置当前容器名称（用于日志文件命名）。
pub fn set_log_container_name(name: &str) {
    if let Ok(mut state) = LOG_STATE.lock() {
        state.container_name = name.to_string();
    }
}

/// 设置容器日志文件描述符（-1 表示未打开）。
pub fn set_log_container_fd(fd: i32) {
    if let Ok(mut state) = LOG_STATE.lock() {
        state.container_fd = fd;
    }
}

/// 获取日志容器 fd 的当前值（用于外部读取）。
pub fn get_log_container_fd() -> i32 {
    LOG_STATE.lock().map(|s| s.container_fd).unwrap_or(-1)
}

/// 打开容器日志文件。
///
/// 对应 C 的 `open_container_log()`。
/// 创建日志目录，轮转过大的日志文件，以 O_APPEND | O_CLOEXEC 模式打开临时日志文件描述符。
pub fn open_container_log(cfg: &Config) -> io::Result<()> {
    if cfg.container_name.is_empty() {
        return Ok(());
    }

    let safe_name = sanitize_container_name(&cfg.container_name);
    let log_dir = format!(
        "{}/{}/{}",
        get_runtime_dir(),
        constants::RUNTIME_LOGS_SUBDIR,
        safe_name
    );
    mkdir_p(Path::new(&log_dir), 0o755)?;

    let log_path = format!("{}/log", log_dir);
    let log_path = Path::new(&log_path);
    rotate_log(log_path, 2 * 1024 * 1024)?;

    // O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).append(true);
    opts.custom_flags(libc::O_CLOEXEC);
    // 权限 0644
    opts.mode(0o644);

    let _file = opts.open(log_path)?;
    // 直接使用原始 fd（不经过 Rust File 的 RAII，因为我们想要长期持有）
    // 使用 libc::open 以获得与 C 代码一致的 fd 生命周期管理
    let log_path_c = CString::new(log_path.to_string_lossy().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let fd = unsafe {
        libc::open(
            log_path_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd >= 0 {
        set_log_container_fd(fd);
    }

    Ok(())
}

/// 关闭容器日志文件描述符。
///
/// 对应 C 的 `close_container_log()`。
pub fn close_container_log() {
    let fd = get_log_container_fd();
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
        set_log_container_fd(-1);
    }
}

/// 打印特权模式警告横幅。
///
/// 对应 C 的 `print_privileged_warning()`。
pub fn print_privileged_warning(privileged_mask: u32) {
    if privileged_mask == 0 {
        return;
    }
    println!(
        "WARNING: PRIVILEGED MODE ACTIVE - DEVICE SECURITY COMPROMISED\r\n"
    );
    let _ = io::stdout().flush();
}

// ══════════════════════════════════════════════════════════════════════════════
// 12. 容器运行时间统计
// ══════════════════════════════════════════════════════════════════════════════

/// 计算容器自启动以来的运行秒数。
///
/// 方法：从 `/proc/<pid>/stat` 的第 22 个字段（starttime）获取启动 tick，
/// 与 `/proc/uptime` 的系统启动时间相减。
///
/// 返回运行秒数，-1 表示错误。
pub fn get_container_uptime(pid: libc::pid_t) -> i64 {
    if pid <= 0 {
        return -1;
    }

    // sysconf(_SC_CLK_TCK) —— CPU 频率（tick 数/秒）
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let clk_tck = if clk_tck > 0 { clk_tck } else { 100 };

    // 读取 /proc/<pid>/stat 的第 22 个字段（starttime）
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = match fs::read_to_string(&stat_path) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    // /proc/<pid>/stat 的格式：PID (COMM) STATE ... 之后用空格分隔
    // 第 22 个字段：starttime
    // 注意：COMM 可能包含空格和括号，需要特殊处理
    let after_comm = match stat_content.find(") ") {
        Some(pos) => &stat_content[pos + 2..],
        None => return -1,
    };

    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // starttime 是第 22 个字段，即 after_comm 的第 19 个（因为 ")" 之后的第一个字段是 state:0，
    // state:1,ppid:2,pgrp:3,session:4,tty_nr:5,tpgid:6,flags:7,minflt:8,cminflt:9,
    // majflt:10,cmajflt:11,utime:12,stime:13,cutime:14,cstime:15,priority:16,
    // nice:17,num_threads:18,itrealvalue:19,starttime:20, ...)
    // 实际上 starttime 是字段索引 20（0-based after_comm）
    let start_ticks: u64 = match fields.get(19) {
        Some(s) => s.parse().unwrap_or(0),
        None => return -1,
    };

    if start_ticks == 0 {
        return -1;
    }

    // 读取 /proc/uptime
    let uptime_content = match fs::read_to_string("/proc/uptime") {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let host_uptime_sec: f64 = uptime_content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    let uptime_sec =
        (host_uptime_sec - (start_ticks as f64) / (clk_tck as f64)) as i64;

    if uptime_sec < 0 {
        0
    } else {
        uptime_sec
    }
}

/// 将秒数格式化为人类可读的运行时间字符串。
///
/// 对应 C 的 `format_uptime()`。
pub fn format_uptime(uptime_sec: i64) -> String {
    if uptime_sec < 0 {
        return "unknown".to_string();
    }

    let days: i64 = uptime_sec / 86400;
    let hours: i64 = (uptime_sec % 86400) / 3600;
    let mins: i64 = (uptime_sec % 3600) / 60;
    let secs: i64 = uptime_sec % 60;

    let mut result = String::new();
    if days > 0 {
        result.push_str(&format!("{}d ", days));
    }
    if hours > 0 || days > 0 {
        result.push_str(&format!("{}h ", hours));
    }
    if mins > 0 || hours > 0 || days > 0 {
        result.push_str(&format!("{}m ", mins));
    }
    result.push_str(&format!("{}s", secs));

    result
}

/// 显示容器资源使用情况（运行时间、CPU%、内存使用）。
///
/// 对应 C 的 `show_container_usage()`。
///
/// 输出机器可解析的 KEY=VALUE 格式：
///   UPTIME_SEC=<seconds>
///   UPTIME=<Xd Xh Xm Xs>
///   RAM_USED_KB=<kb>
///   RAM_TOTAL_KB=<kb>
///   CPU_PERMILL=<0-1000>
pub fn show_container_usage(cfg: &Config) -> io::Result<()> {
    let pid = crate::pid::is_container_running(cfg)?;
    if pid <= 0 {
        log_error!("Container '{}' is not running.", cfg.container_name);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "container not running",
        ));
    }

    // ── UPTIME ──
    let uptime_sec = get_container_uptime(pid);
    let uptime_str = format_uptime(uptime_sec);

    // ── PID namespace of container init ──
    let ns_init_path = format!("/proc/{}/ns/pid", pid);
    let container_ns = fs::read_link(&ns_init_path)
        .map_err(|e| {
            log_error!(
                "Failed to read PID namespace of container init: {}",
                e
            );
            e
        })?;
    let container_ns_str = container_ns.to_string_lossy().to_string();

    // ── WALK 1: 在一次 /proc 遍历中收集 RAM + CPU 样本 1 ──
    let mut ram_used_kb: i64 = 0;
    let mut cpu_t1: i64 = 0;
    let mut cpu_host_t1: i64 = 0;

    let proc_dir = fs::read_dir("/proc")?;
    for entry in proc_dir {
        let entry = entry?;
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        // 仅处理数字条目（PID）
        if !fname_str.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            continue;
        }

        // 检查 PID namespace
        let ns_path = format!("/proc/{}/ns/pid", fname_str);
        if let Ok(ns_link) = fs::read_link(&ns_path) {
            if ns_link.to_string_lossy() != container_ns_str.as_str() {
                continue;
            }

            // RAM: VmRSS from /proc/<pid>/status
            if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", fname_str)) {
                for line in status.lines() {
                    if let Some(vmline) = line.strip_prefix("VmRSS:") {
                        if let Some(val_str) = vmline.split_whitespace().next() {
                            if let Ok(val) = val_str.parse::<i64>() {
                                ram_used_kb += val;
                            }
                        }
                        break;
                    }
                }
            }

            // CPU sample 1: utime+stime from /proc/<pid>/stat fields 14+15
            if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", fname_str)) {
                let after_comm = match stat.find(") ") {
                    Some(pos) => &stat[pos + 2..],
                    None => continue,
                };
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // utime: field index 11 (0-based after_comm), stime: field index 12
                if let (Some(utime_str), Some(stime_str)) = (fields.get(11), fields.get(12)) {
                    let utime: i64 = utime_str.parse().unwrap_or(0);
                    let stime: i64 = stime_str.parse().unwrap_or(0);
                    cpu_t1 += utime + stime;
                }
            }
        }
    }

    // host CPU total sample 1 from /proc/stat
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        if let Some(line) = stat.lines().next() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // "cpu user nice system idle iowait irq softirq ..."
            if parts.len() >= 8 && parts[0] == "cpu" {
                for &p in &parts[1..8] {
                    cpu_host_t1 += p.parse::<i64>().unwrap_or(0);
                }
            }
        }
    }

    // total device RAM from /proc/meminfo
    let mut ram_total_kb: i64 = 0;
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(memline) = line.strip_prefix("MemTotal:") {
                if let Some(val_str) = memline.split_whitespace().next() {
                    ram_total_kb = val_str.parse().unwrap_or(0);
                }
                break;
            }
        }
    }

    // 250ms 测量窗口
    std::thread::sleep(std::time::Duration::from_millis(250));

    // ── WALK 2: CPU 样本 2 only ──
    let mut cpu_t2: i64 = 0;
    let mut cpu_host_t2: i64 = 0;

    let proc_dir = fs::read_dir("/proc")?;
    for entry in proc_dir {
        let entry = entry?;
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        if !fname_str.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            continue;
        }

        let ns_path = format!("/proc/{}/ns/pid", fname_str);
        if let Ok(ns_link) = fs::read_link(&ns_path) {
            if ns_link.to_string_lossy() != container_ns_str.as_str() {
                continue;
            }

            if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", fname_str)) {
                let after_comm = match stat.find(") ") {
                    Some(pos) => &stat[pos + 2..],
                    None => continue,
                };
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                if let (Some(utime_str), Some(stime_str)) = (fields.get(11), fields.get(12)) {
                    let utime: i64 = utime_str.parse().unwrap_or(0);
                    let stime: i64 = stime_str.parse().unwrap_or(0);
                    cpu_t2 += utime + stime;
                }
            }
        }
    }

    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        if let Some(line) = stat.lines().next() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 && parts[0] == "cpu" {
                for &p in &parts[1..8] {
                    cpu_host_t2 += p.parse::<i64>().unwrap_or(0);
                }
            }
        }
    }

    let mut delta_container = cpu_t2 - cpu_t1;
    let delta_host = cpu_host_t2 - cpu_host_t1;
    if delta_container < 0 {
        delta_container = 0;
    }
    let cpu_permill = if delta_host > 0 {
        (delta_container * 1000 / delta_host).min(1000)
    } else {
        0
    };

    // ── Output ──
    println!("UPTIME_SEC={}", uptime_sec);
    println!("UPTIME={}", uptime_str);
    println!("RAM_USED_KB={}", ram_used_kb);
    println!("RAM_TOTAL_KB={}", ram_total_kb);
    println!("CPU_PERMILL={}", cpu_permill);

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// 13. Bind Mount 排序
// ══════════════════════════════════════════════════════════════════════════════

/// 按目标路径排序 bind mount 条目（升序）。
///
/// 对应 C 的 `sort_bind_mounts()` + `compare_bind_mounts()`。
pub fn sort_bind_mounts(cfg: &mut Config) {
    if cfg.binds.len() <= 1 {
        return;
    }
    cfg.binds.sort_by(|a, b| a.dest.cmp(&b.dest));
}

// ══════════════════════════════════════════════════════════════════════════════
// 14. 名称验证
// ══════════════════════════════════════════════════════════════════════════════

/// 验证容器名称是否合法。
///
/// 合法的名称包含：字母、数字、`.`、`_`、`-` 和空格。
/// 长度为 1..255 个字符，不允许单独的 `.` 或 `..`。
pub fn validate_container_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    if name == "." || name == ".." {
        return false;
    }

    if name.len() >= 256 {
        return false;
    }

    for c in name.chars() {
        if !c.is_alphanumeric() && c != '.' && c != '_' && c != '-' && c != ' ' {
            return false;
        }
    }

    true
}

/// 验证并拒绝非法容器名称，打印错误信息。
///
/// 对应 C 的 `reject_container_name()`。
/// 返回 `Ok(())` 表示名称合法，`Err` 表示不合法。
pub fn reject_container_name(name: &str) -> io::Result<()> {
    if !validate_container_name(name) {
        log_error!(
            "Invalid container name '{}'. Use only letters, numbers, '.', '_', '-' and spaces.",
            name
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid container name",
        ));
    }
    Ok(())
}

/// 验证 bind mount 目标路径。
///
/// 必须是以 `/` 开头的绝对路径，不能是单独的 `/`，
/// 长度必须不超过 PATH_MAX，路径组件不能是 `.` 或 `..`。
pub fn validate_bind_destination(dest: &str) -> bool {
    if dest.is_empty() || !dest.starts_with('/') || dest == "/" {
        return false;
    }

    if dest.len() >= libc::PATH_MAX as usize {
        return false;
    }

    // 按 '/' 分割验证每个组件
    for comp in dest.split('/').filter(|s| !s.is_empty()) {
        if comp == "." || comp == ".." {
            return false;
        }
        // 不允许控制字符
        if comp.chars().any(|c| c.is_control()) {
            return false;
        }
    }

    true
}

// ══════════════════════════════════════════════════════════════════════════════
// 15. 大小解析/格式化
// ══════════════════════════════════════════════════════════════════════════════

/// 解析人类可读的大小字符串："512M"、"1G"、"2048"（字节）。
///
/// 整数部分和分数部分分开处理，避免大数值（如 8192G 超过 double 的 53 位尾数）的精度损失：
/// - 整数部分：精确的 `i64` 运算
/// - 分数部分（如 "1.5G"）：仅对子单位部分进行有限的 double 乘法，精度损失 <1 字节
///
/// 返回 `Some(bytes)` 成功解析，`None` 格式错误。
pub fn parse_size(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }

    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // 解析整数部分
    let (int_part_str, remaining) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(s.len()),
    );

    if int_part_str.is_empty() {
        return None;
    }

    let int_part: i64 = int_part_str.parse().ok()?;
    if int_part < 0 {
        return None;
    }

    // 可选的分数部分（如 "1.5G" 中的 ".5"）
    let (frac, remaining) = if let Some(dot_rem) = remaining.strip_prefix('.') {
        let (frac_str, rest) = dot_rem.split_at(
            dot_rem
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(dot_rem.len()),
        );
        if frac_str.is_empty() {
            return None;
        }
        let f: f64 = format!("0.{}", frac_str).parse().ok()?;
        if f < 0.0 {
            return None;
        }
        (f, rest)
    } else {
        (0.0, remaining)
    };

    // 单位后缀
    let factor: i64 = if remaining.is_empty() {
        1
    } else {
        let unit = remaining.to_lowercase();
        match unit.as_str() {
            "k" | "kb" => 1024,
            "m" | "mb" => 1024 * 1024,
            "g" | "gb" => 1024 * 1024 * 1024,
            "t" | "tb" => 1024_i64 * 1024 * 1024 * 1024,
            _ => return None, // 未知单位
        }
    };

    // 溢出检查
    if factor > 1 && int_part > i64::MAX / factor {
        return None;
    }

    let mut result = int_part * factor;
    if frac != 0.0 {
        result += (frac * (factor as f64)) as i64;
    }

    Some(result)
}

/// 将字节数格式化为人类可读的字符串。
///
/// 对应 C 的 `format_size()`。
pub fn format_size(bytes: i64) -> String {
    if bytes <= 0 {
        return "N/A".to_string();
    }

    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut u = 0usize;
    let mut d = bytes as f64;
    while d >= 1024.0 && u < 4 {
        d /= 1024.0;
        u += 1;
    }

    format!("{:.2} {}", d, units[u])
}

// ══════════════════════════════════════════════════════════════════════════════
// 16. 文件夹计数
// ══════════════════════════════════════════════════════════════════════════════

/// 统计目录中直接子目录的数量。
///
/// 对应 C 的 `count_folders()`。
pub fn count_folders(path: &Path) -> io::Result<usize> {
    let dir = match fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return Ok(0),
    };

    let mut count: usize = 0;
    for entry in dir {
        let entry = entry?;
        let ftype = entry.file_type()?;
        if ftype.is_dir() {
            count += 1;
        }
    }
    Ok(count)
}

// ══════════════════════════════════════════════════════════════════════════════
// 17. 多名称解析与验证
// ══════════════════════════════════════════════════════════════════════════════

/// 验证逗号分隔的容器名称列表中的每一个名称。
///
/// 对应 C 的 `parse_and_validate_names()`。
pub fn parse_and_validate_names(optarg: &str) -> io::Result<String> {
    for name in optarg.split(',') {
        let name = name.trim();
        if !name.is_empty() {
            reject_container_name(name)?;
        }
    }
    Ok(optarg.to_string())
}

/// 停止多个逗号分隔名称的容器。
///
/// 对应 C 的 `multi_stop()`。
///
/// 注意：原始 C 实现里 `multi_stop()` 只是把 `container_name` 填进一个全零的
/// `struct config` 就直接调 `stop_rootfs()`，从未加载磁盘上持久化的配置，
/// 导致 `cfg->uuid` 始终为空 —— 而 `is_container_running()` 一旦看到空 UUID
/// 就直接判定"未运行"。这意味着 C 版本的 `multi_stop` 实际上对任何容器都会
/// 报"not running"，是上游本身的一个潜在 bug。这里顺手修正：调用前先
/// `config_load_by_name()` 把该容器名对应的持久化配置（包含 UUID）加载进来，
/// 这也是 `main.c`/`main.rs` 里单容器 `stop` 路径一直在做的事。
/// 另外改为遍历全部名称、失败也继续处理下一个、最后汇总结果，
/// 对齐 C 版"尽力而为，最后返回是否有失败"的语义，而不是遇到第一个错误就退出。
pub fn multi_stop(raw_names: &str) -> io::Result<()> {
    let mut any_failed = false;

    for name in raw_names.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }

        let mut cfg = Config {
            container_name: name.to_string(),
            ..Default::default()
        };
        // 加载该容器名对应的持久化配置（uuid、img_mount_point 等）。
        // 加载失败（比如从未启动过这个名字）不致命——交给 stop_rootfs
        // 自己去判定"未运行"并打印准确的错误信息。
        let _ = crate::config::config_load_by_name(name, &mut cfg);

        if crate::container::stop_rootfs(&mut cfg, false) != 0 {
            any_failed = true;
        }
    }

    if any_failed {
        Err(io::Error::other("one or more containers failed to stop"))
    } else {
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 18. OOM 防护
// ══════════════════════════════════════════════════════════════════════════════

/// 设置 oom_score_adj 为 -1000（使进程不被 OOM killer 杀死）。
///
/// 对应 C 的 `oom_protect()`。
/// Best-effort：失败时不返回错误。
pub fn oom_protect() {
    if let Ok(mut f) = fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/oom_score_adj") {
        let _ = f.write_all(b"-1000\n");
    }
}
