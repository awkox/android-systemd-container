//! 终端/PTY 操作 —— 对应原 terminal.c。
//!
//! 提供 PTY 分配（openpty）、TTY 创建、标准 fd 重定向、控制终端设置、
//! 以及 raw 模式终端配置。
//!
//! # PTY 分配策略
//!
//! 1. 打开 `/dev/ptmx`（O_RDWR | O_NOCTTY | O_CLOEXEC）
//! 2. TIOCSPTLCK 解锁（best-effort）
//! 3. TIOCGPTPEER（Linux 4.13+）直接从 master fd 打开 slave
//! 4. 回退：TIOCGPTN 获取编号 + 手动打开 `/dev/pts/N`

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

use crate::constants;
use crate::types::TtyInfo;
use crate::log_error;

// ── PTY 分配 ──

/// 打开 PTY master + slave，不依赖 `/dev/ptmx` 符号链接解析。
///
/// 优先使用 TIOCGPTPEER（Linux 4.13+）直接从 master fd 打开 slave，
/// 回退到 TIOCGPTN + 路径打开（兼容 3.x 内核）。
///
/// 返回 `(master_fd, slave_fd, slave_path)`。
pub fn openpty() -> io::Result<(RawFd, RawFd, Option<String>)> {
    let ptmx = CString::new("/dev/ptmx").expect("valid path");
    let m = unsafe {
        libc::open(
            ptmx.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if m < 0 {
        return Err(io::Error::last_os_error());
    }

    // best-effort 解锁：某些厂商 4.9 内核在 newinstance devpts 挂载上可能返回
    // EINVAL/EIO，内核需要时自动解锁
    let unlock: libc::c_int = 0;
    unsafe {
        libc::ioctl(m, libc::TIOCSPTLCK, &unlock);
    }

    // 尝试 Linux 4.13+ 的无路径方法
    let s = unsafe {
        libc::ioctl(
            m,
            libc::TIOCGPTPEER,
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };

    if s >= 0 {
        // TIOCGPTPEER 成功
        let mut ptyno: libc::c_uint = 0;
        unsafe {
            libc::ioctl(m, libc::TIOCGPTN, &mut ptyno);
        }
        let name = format!("/dev/pts/{}", ptyno);
        Ok((m, s, Some(name)))
    } else {
        // 回退：TIOCGPTN + 路径打开
        let mut ptyno: libc::c_uint = 0;
        if unsafe { libc::ioctl(m, libc::TIOCGPTN, &mut ptyno) } < 0 {
            unsafe { libc::close(m) };
            return Err(io::Error::last_os_error());
        }

        let name = format!("/dev/pts/{}", ptyno);
        let pts_path = CString::new(name.as_str())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let s_new = unsafe {
            libc::open(
                pts_path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if s_new < 0 {
            unsafe { libc::close(m) };
            return Err(io::Error::last_os_error());
        }
        Ok((m, s_new, Some(name)))
    }
}

/// 使用已分配的 PTY 填充 `TtyInfo` 结构。
///
/// 调用 `openpty()`，设置 slave tty 的组所有权（gid=5）+ 权限 0620。
pub fn terminal_create(tty: &mut TtyInfo) -> io::Result<()> {
    let (master, slave, name) = openpty()?;

    // tty 组所有权 + 权限
    // gid = DEFAULT_TTY_GID (5), best-effort
    let _ = unsafe { libc::fchown(slave, 0, constants::DEFAULT_TTY_GID) };
    unsafe {
        libc::fchmod(slave, 0o620);
    }

    tty.master = master;
    tty.slave = slave;
    if let Some(n) = name {
        tty.name = n.into();
    }

    Ok(())
}

// ── 标准 fd 重定向 ──

/// 将 stdin/stdout/stderr 重定向到给定 fd。
///
/// 对应 C 的 `terminal_set_stdfds()`。
/// 使用 `dup2(2)` 依次替换三个标准流。
pub fn terminal_set_stdfds(fd: RawFd) -> io::Result<()> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::dup2(fd, libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::dup2(fd, libc::STDERR_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ── 控制终端 ──

/// 将 fd 设置为进程的新控制终端。
///
/// 先调用 `setsid()` 丢弃现有控制终端和会话，
/// 再使用 `TIOCSCTTY` ioctl 将 fd 设为新的控制终端。
///
/// TIOCSCTTY 的参数设为 0（强制为当前进程）。
pub fn terminal_make_controlling(fd: RawFd) -> io::Result<()> {
    // 丢弃现有控制终端和会话
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }

    // TIOCSCTTY: 将 fd 设为新的控制终端
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY, std::ptr::null::<libc::c_void>()) } < 0 {
        log_error!(
            "TIOCSCTTY failed: {}",
            io::Error::last_os_error()
        );
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ── Raw 模式终端设置 ──

/// 将终端设为 raw 模式，返回旧的 termios 设置以便调用方恢复。
///
/// 对应 C 的 `setup_tios()`。
///
/// Raw 模式镜像 LXC/SSH 的设置以最大化兼容性：
/// - 输入标志：保留 IGNPAR，清除 ISTRIP/INLCR/IGNCR/ICRNL/IXON/IXANY/IXOFF/IUCLC
/// - 本地标志：清除 TOSTOP/ISIG/ICANON/ECHO/ECHOE/ECHOK/ECHONL/IEXTEN
/// - 输出标志：清除 OPOST/ONLCR（防止主 PTY line discipline 将 \n→\r\n，破坏 TUI 转义序列）
/// - 控制字符：VMIN=1, VTIME=0
///
/// 容器 shell 在内部 slave 上自行设置 ONLCR，确保 \r\n 转换只发生一次。
pub fn setup_tios(fd: RawFd) -> io::Result<libc::termios> {
    // isatty 检查
    if unsafe { libc::isatty(fd) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "file descriptor is not a terminal",
        ));
    }

    // 保存旧设置
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // 忽略过渡期间的信号
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    let mut new_tios = old;

    // ── 输入标志 ──
    // IGNPAR: 忽略校验错误
    // 清除: ISTRIP(去除第8位), INLCR(将NL转CR), IGNCR(忽略CR),
    //        ICRNL(将CR转NL), IXON(输出流控), IXANY(任意字符重启), IXOFF(输入流控)
    new_tios.c_iflag |= libc::IGNPAR;
    new_tios.c_iflag &= !(libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON
        | libc::IXANY
        | libc::IXOFF);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        new_tios.c_iflag &= !libc::IUCLC;
    }

    // ── 本地标志 ──
    // 清除: TOSTOP(后台输出信号), ISIG(信号字符), ICANON(规范模式),
    //        ECHO(回显), ECHOE(删除回显), ECHOK(kill回显), ECHONL(nl回显)
    new_tios.c_lflag &= !(libc::TOSTOP
        | libc::ISIG
        | libc::ICANON
        | libc::ECHO
        | libc::ECHOE
        | libc::ECHOK
        | libc::ECHONL);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        new_tios.c_lflag &= !libc::IEXTEN;
    }

    // ── 输出标志 ──
    // 关键：禁用 OPOST/ONLCR 防止主 PTY line discipline 将 \n→\r\n，
    // 这会破坏 tmux、vim 等工具的 TUI 转义序列。
    // 容器 shell 在内部 slave 上自行设置 ONLCR，确保转换只发生一次。
    new_tios.c_oflag &= !(libc::OPOST | libc::ONLCR);

    // ── 控制字符 ──
    // VMIN=1: read 在至少 1 字节可用时立即返回
    // VTIME=0: 无超时
    new_tios.c_cc[libc::VMIN] = 1;
    new_tios.c_cc[libc::VTIME] = 0;

    // 应用新设置（TCSAFLUSH: 排空未读输入后应用）
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &new_tios) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(old)
}
