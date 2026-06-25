//! 守护进程 + 客户端模式 —— 对应原 daemon.c。

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Mutex;

use crate::constants;
use crate::utils::{oom_protect, rotate_log};
use crate::{log_error, log_info};

const MSG_OUT: u8 = 0x01;
const MSG_ERR: u8 = 0x02;
const MSG_WINCH: u8 = 0x03;
const MSG_EXIT: u8 = 0xFF;
const REQ_FLAG_PTY: u32 = 1 << 0;
const IOBUF: usize = 8192;
const MAX_ARGC: usize = 64;

static G_SELF_PATH: Mutex<String> = Mutex::new(String::new());

// ── Wire protocol ──

fn read_exact(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut libc::c_void, buf.len() - off) };
        if n <= 0 { return Err(io::Error::last_os_error()); }
        off += n as usize;
    }
    Ok(())
}

fn send_frame(fd: RawFd, typ: u8, data: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = typ;
    let len = (data.len() as u32).to_be_bytes();
    hdr[1..5].copy_from_slice(&len);
    unsafe { crate::utils::write_all_raw(fd, &hdr)? };
    if !data.is_empty() { unsafe { crate::utils::write_all_raw(fd, data)? }; }
    Ok(())
}

fn send_exit(fd: RawFd, code: i32) {
    let nc = (code as u32).to_be_bytes();
    let _ = send_frame(fd, MSG_EXIT, &nc);
}

fn recv_frame_hdr(fd: RawFd) -> io::Result<(u8, u32)> {
    let mut hdr = [0u8; 5];
    read_exact(fd, &mut hdr)?;
    Ok((hdr[0], u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]])))
}

// ── Abstract socket ──

fn make_addr(addr: &mut libc::sockaddr_un) -> libc::socklen_t {
    unsafe { std::ptr::write_bytes(addr, 0, 1) };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = constants::PROJECT_NAME.as_bytes();
    addr.sun_path[1..1 + name.len()].copy_from_slice(name);
    (mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t
}

// ── Daemonize ──

fn daemonize(foreground: bool) {
    if !foreground {
        let pid = unsafe { libc::fork() };
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); }
        if unsafe { libc::setsid() } < 0 { std::process::exit(1); }
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        let pid = unsafe { libc::fork() };
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); }
    }
    unsafe { libc::umask(0); libc::chdir(c"/".as_ptr()) };
    if !foreground {
        let dn = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if dn >= 0 { unsafe { libc::dup2(dn, libc::STDIN_FILENO) }; if dn > libc::STDERR_FILENO { unsafe { libc::close(dn); } } }
    }

    let log_path = format!("{}/ds-forkd.log", crate::pid::get_logs_dir());
    let _ = rotate_log(Path::new(&log_path), 2 * 1024 * 1024);
    if !foreground {
        let lp = CString::new(log_path.as_str()).unwrap();
        let lfd = unsafe { libc::open(lp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC, 0o644) };
        if lfd >= 0 {
            unsafe { libc::dup2(lfd, libc::STDOUT_FILENO); libc::dup2(lfd, libc::STDERR_FILENO); }
            if lfd > libc::STDERR_FILENO { unsafe { libc::close(lfd); } }
        }
    }
    oom_protect();
}

fn reexec(argv: &[CString]) -> ! {
    let path = G_SELF_PATH.lock().unwrap();
    let exe = if !path.is_empty() { path.as_str() } else { "/proc/self/exe" };
    let exe_c = CString::new(exe).unwrap();
    let mut c_args: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    c_args.push(std::ptr::null());
    unsafe { libc::execv(exe_c.as_ptr(), c_args.as_ptr()) };
    unsafe { libc::_exit(127) };
}

// ── Request ──

struct Request {
    flags: u32,
    argv: Vec<String>,
    rows: u16,
    cols: u16,
}

fn recv_req(fd: RawFd) -> io::Result<Request> {
    let (mut nf, mut na) = ([0u8; 4], [0u8; 4]);
    read_exact(fd, &mut nf)?; read_exact(fd, &mut na)?;
    let flags = u32::from_be_bytes(nf);
    let argc = u32::from_be_bytes(na) as usize;
    if argc == 0 || argc > MAX_ARGC { return Err(io::Error::other("bad argc")); }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let mut nb = [0u8; 4]; read_exact(fd, &mut nb)?;
        let al = u32::from_be_bytes(nb) as usize;
        if al > 8192 { return Err(io::Error::other("arg too long")); }
        let mut ab = vec![0u8; al];
        if al > 0 { read_exact(fd, &mut ab)?; }
        argv.push(String::from_utf8_lossy(&ab).to_string());
    }
    let (rows, cols) = if flags & REQ_FLAG_PTY != 0 {
        let mut ws = [0u8; 4]; read_exact(fd, &mut ws)?;
        (u16::from_be_bytes([ws[0], ws[1]]).max(24), u16::from_be_bytes([ws[2], ws[3]]).max(80))
    } else { (24, 80) };
    Ok(Request { flags, argv, rows, cols })
}

// ── Session ──

fn handle_session(conn: RawFd, r: &Request) {
    let is_pty = r.flags & REQ_FLAG_PTY != 0;
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let mut out = [-1, -1];
    let mut err = [-1, -1];

    if is_pty {
        match crate::terminal::openpty() {
            Ok((m, s, _)) => { master = m; slave = s; }
            Err(_) => { send_exit(conn, 1); return; }
        }
        let ws = libc::winsize { ws_row: r.rows, ws_col: r.cols, ws_xpixel: 0, ws_ypixel: 0 };
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
        unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) };
    } else {
        if unsafe { libc::pipe2(out.as_mut_ptr(), libc::O_CLOEXEC) } < 0
            || unsafe { libc::pipe2(err.as_mut_ptr(), libc::O_CLOEXEC) } < 0
        { send_exit(conn, 1); return; }
    }

    let av: Vec<CString> = std::iter::once(CString::new(constants::PROJECT_NAME).unwrap())
        .chain(r.argv.iter().map(|a| CString::new(a.as_str()).unwrap_or_default()))
        .collect();

    let child = unsafe { libc::fork() };
    if child < 0 { send_exit(conn, 1); return; }

    if child == 0 {
        unsafe { libc::close(conn) };
        if is_pty {
            unsafe { libc::close(master); libc::setsid(); libc::ioctl(slave, libc::TIOCSCTTY, 0) };
            unsafe { libc::dup2(slave, libc::STDIN_FILENO); libc::dup2(slave, libc::STDOUT_FILENO); libc::dup2(slave, libc::STDERR_FILENO) };
            if slave > libc::STDERR_FILENO { unsafe { libc::close(slave); } }
        } else {
            unsafe { libc::close(out[0]); libc::close(err[0]) };
            let dn = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            if dn >= 0 { unsafe { libc::dup2(dn, libc::STDIN_FILENO) }; if dn > libc::STDERR_FILENO { unsafe { libc::close(dn); } } }
            unsafe { libc::dup2(out[1], libc::STDOUT_FILENO); libc::dup2(err[1], libc::STDERR_FILENO); libc::close(out[1]); libc::close(err[1]) };
        }
        unsafe { libc::setenv(c"NO_PROXY".as_ptr(), c"1".as_ptr(), 1) };
        for &s in &[libc::SIGHUP, libc::SIGPIPE, libc::SIGCHLD] { unsafe { libc::signal(s, libc::SIG_DFL) }; }
        reexec(&av);
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 { unsafe { libc::kill(child, libc::SIGTERM); libc::waitpid(child, std::ptr::null_mut(), 0) }; send_exit(conn, 1); return; }

    let mut ev: libc::epoll_event = unsafe { mem::zeroed() };
    let mut active_reads;

    if is_pty {
        // 父进程不再需要 slave 端——子进程已经把它 dup 成了自己的 stdio。
        // 必须关闭，否则父进程自己残留的这一份引用会让 master 永远等不到
        // EPOLLHUP（PTY 的 slave 端只要还有任何进程打开着，内核就不会
        // 认为它"已经没人在用"）。
        unsafe { libc::close(slave) };
        let fl = unsafe { libc::fcntl(master, libc::F_GETFL) };
        unsafe { libc::fcntl(master, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
        ev.u64 = master as u64;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, master, &mut ev) };
        active_reads = 1;
    } else {
        // 同理：父进程关闭自己的写端拷贝，否则子进程退出后 out[0]/err[0]
        // 永远读不到 EOF（父进程自己的写端引用还活着）。
        unsafe { libc::close(out[1]); libc::close(err[1]) };
        out[1] = -1; err[1] = -1;
        unsafe { libc::fcntl(out[0], libc::F_SETFL, libc::O_NONBLOCK) };
        unsafe { libc::fcntl(err[0], libc::F_SETFL, libc::O_NONBLOCK) };
        ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
        ev.u64 = out[0] as u64;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, out[0], &mut ev) };
        ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
        ev.u64 = err[0] as u64;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, err[0], &mut ev) };
        active_reads = 2;
    }

    let sfd = {
        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe { libc::sigaddset(&mut mask, libc::SIGCHLD) };
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
        unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) }
    };

    if sfd >= 0 { ev.events = libc::EPOLLIN as u32; ev.u64 = sfd as u64; unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sfd, &mut ev) }; }
    ev.events = (if is_pty { libc::EPOLLIN } else { 0 } | libc::EPOLLHUP | libc::EPOLLERR) as u32; ev.u64 = conn as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, conn, &mut ev) };

    let mut exit_code = -1i32;
    let mut child_done: i32 = 0;
    let mut events: [libc::epoll_event; 8] = unsafe { mem::zeroed() };
    let mut buf = [0u8; IOBUF];

    loop {
        let nfds = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 8, -1) };
        if nfds < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) { break; }
        for i in 0..nfds {
            let fd = events[i as usize].u64 as RawFd;
            if sfd >= 0 && fd == sfd {
                let mut si: libc::signalfd_siginfo = unsafe { mem::zeroed() };
                while unsafe { libc::read(sfd, &mut si as *mut _ as *mut libc::c_void, mem::size_of::<libc::signalfd_siginfo>()) }
                    == mem::size_of::<libc::signalfd_siginfo>() as isize {
                    if child_done == 0 {
                        let mut st = 0;
                        if unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) } == child {
                            exit_code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 };
                            child_done = 1;
                        }
                    }
                }
            } else if fd == conn {
                if events[i as usize].events & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0 {
                    unsafe { libc::kill(child, if is_pty { libc::SIGHUP } else { libc::SIGTERM }); libc::waitpid(child, std::ptr::null_mut(), 0) };
                    break;
                }
                if is_pty && events[i as usize].events & libc::EPOLLIN as u32 != 0 {
                    if let Ok((typ, mlen)) = recv_frame_hdr(conn) {
                        if typ == MSG_OUT && mlen > 0 && mlen <= IOBUF as u32 {
                            let mut dbuf = vec![0u8; mlen as usize];
                            if read_exact(conn, &mut dbuf).is_ok() { let _ = unsafe { crate::utils::write_all_raw(master, &dbuf) }; }
                        } else if typ == MSG_WINCH && mlen == 4 {
                            let mut wd = [0u8; 4];
                            if read_exact(conn, &mut wd).is_ok() {
                                let nws = libc::winsize { ws_row: u16::from_be_bytes([wd[0], wd[1]]), ws_col: u16::from_be_bytes([wd[2], wd[3]]), ws_xpixel: 0, ws_ypixel: 0 };
                                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &nws); libc::kill(child, libc::SIGWINCH) };
                            }
                        }
                    }
                }
            } else if is_pty && fd == master {
                if events[i as usize].events & (libc::EPOLLIN | libc::EPOLLHUP) as u32 != 0 {
                    loop {
                        let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                        if n > 0 { if send_frame(conn, MSG_OUT, &buf[..n as usize]).is_err() { break; } }
                        else { break; }
                    }
                }
            } else if (fd == out[0] || fd == err[0])
                && events[i as usize].events & (libc::EPOLLIN | libc::EPOLLHUP) as u32 != 0 {
                    let mut drained = false;
                    loop {
                        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                        if n > 0 {
                            let t = if fd == err[0] { MSG_ERR } else { MSG_OUT };
                            if send_frame(conn, t, &buf[..n as usize]).is_err() { break; }
                        } else if n == 0 { drained = true; break; }
                        else { break; }
                    }
                    if drained {
                        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()); libc::close(fd) };
                        active_reads -= 1;
                        if active_reads <= 0 { child_done = 2; }
                    }
                }
        }
        if child_done != 0 { break; }
    }

    if exit_code == -1 { let mut st = 0; unsafe { libc::waitpid(child, &mut st, 0) }; exit_code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 }; }
    if sfd >= 0 { unsafe { libc::close(sfd) }; }
    unsafe { libc::close(epfd) };
    if master >= 0 { unsafe { libc::close(master) }; }
    for &fd in &[out[0], err[0]] { if fd >= 0 { unsafe { libc::close(fd) }; } }
    send_exit(conn, exit_code);
}

// ── Connection handler ──

fn handle_conn(conn: RawFd) -> ! {
    let req = match recv_req(conn) {
        Ok(r) => r,
        Err(_) => { send_exit(conn, 1); unsafe { libc::close(conn); libc::_exit(1) } }
    };
    for (i, arg) in req.argv.iter().enumerate() {
        if i > 0 && req.argv[i - 1].starts_with('-') { continue; }
        if arg == "daemon" || arg == "client" { send_exit(conn, 1); unsafe { libc::close(conn); libc::_exit(1) } }
    }
    log_info!("Client connected. Mode: {}", if req.flags & REQ_FLAG_PTY != 0 { "PTY" } else { "PIPE" });
    handle_session(conn, &req);
    log_info!("Session finished.");
    unsafe { libc::close(conn); libc::_exit(0) };
}

// ── Client (代理客户端) ──

/// 把整条命令代理给后台 daemon 进程执行。
///
/// 对应 C 的 `client_run()`（daemon.c）。这个函数此前在 Rust 重写里完全缺失——
/// `daemon_run`/`handle_session` 服务端写得很完整，但客户端从未存在过，
/// 导致 daemon 这套 IPC 子系统从客户端视角是不可达的孤岛。
///
/// 返回值约定（与 C 版本一致，main.rs 据此判断是走代理结果还是回退到本地执行）：
///   -2  daemon 不可达（未监听 / 连接被拒），调用方应回退到本地直接执行；
///   -1  保留（当前实现不会返回，C 版本里 argc<1 时返回，这里 main.rs 永远不会传空 args）；
///    其它  daemon 会话的真实退出码（0 表示成功）。
pub fn client_run(args: &[String]) -> i32 {
    if args.is_empty() {
        return -2;
    }

    let mut argv: Vec<String> = args.to_vec();

    let mut interactive = argv.iter().any(|a| a == "start" || a == "restart");

    let has_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 && libc::isatty(libc::STDOUT_FILENO) != 0 };

    if interactive && !has_tty {
        let forces_tty = argv.iter().any(|a| a == "-f" || a == "--foreground")
            && argv.iter().any(|a| a == "start" || a == "restart");
        if forces_tty {
            // 去掉 -f/--foreground：start_rootfs() 自己会发现没有交互终端，
            // 打印警告并把 foreground 开关翻回去，这里只是避免把一个没意义的
            // 标志发给 daemon。
            argv.retain(|a| a != "-f" && a != "--foreground");
        }
        interactive = false;
    }

    // 连接 daemon（抽象 socket）
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        eprintln!("client: socket: {}", io::Error::last_os_error());
        return 1;
    }
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let alen = make_addr(&mut addr);
    if unsafe { libc::connect(sock, &addr as *const libc::sockaddr_un as *const libc::sockaddr, alen) } < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return match err.raw_os_error() {
            Some(libc::ECONNREFUSED) | Some(libc::ENOENT) => -2, // daemon 没在监听
            _ => {
                eprintln!("[-] Connection to daemon failed: {}", err);
                1
            }
        };
    }

    // 发送请求帧：flags + argc + 每个参数（4 字节长度前缀 + 内容）
    macro_rules! send_or_err {
        ($buf:expr) => {
            if unsafe { crate::utils::write_all_raw(sock, $buf) }.is_err() {
                eprintln!("client: send failed: {}", io::Error::last_os_error());
                unsafe { libc::close(sock) };
                return 1;
            }
        };
    }

    let flags: u32 = if interactive { REQ_FLAG_PTY } else { 0 };
    send_or_err!(&flags.to_be_bytes());
    send_or_err!(&(argv.len() as u32).to_be_bytes());
    for a in &argv {
        let bytes = a.as_bytes();
        send_or_err!(&(bytes.len() as u32).to_be_bytes());
        if !bytes.is_empty() {
            send_or_err!(bytes);
        }
    }

    if interactive {
        let mut ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
        let mut wd = [0u8; 4];
        wd[0..2].copy_from_slice(&ws.ws_row.to_be_bytes());
        wd[2..4].copy_from_slice(&ws.ws_col.to_be_bytes());
        send_or_err!(&wd);
    }

    // ── relay 循环 ──
    let mut orig: libc::termios = unsafe { mem::zeroed() };
    let mut raw_tty_active = false;
    let mut winch_sfd: RawFd = -1;

    if interactive && has_tty && unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut orig) } == 0 {
        raw_tty_active = true;
        let mut raw = orig;
        unsafe { libc::cfmakeraw(&mut raw) };
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw) };

        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGWINCH);
            libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
        }
        winch_sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let mut ev: libc::epoll_event = unsafe { mem::zeroed() };

    if raw_tty_active {
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = libc::STDIN_FILENO as u64;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, libc::STDIN_FILENO, &mut ev) };
    }
    if winch_sfd >= 0 {
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = winch_sfd as u64;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, winch_sfd, &mut ev) };
    }
    ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = sock as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sock, &mut ev) };

    let mut exit_code = 0i32;
    let mut buf = [0u8; IOBUF];
    let mut events: [libc::epoll_event; 4] = unsafe { mem::zeroed() };

    'outer: loop {
        let nfds = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 4, -1) };
        if nfds < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }

        for i in 0..nfds.max(0) {
            let fd = events[i as usize].u64 as RawFd;

            if winch_sfd >= 0 && fd == winch_sfd {
                let mut si: libc::signalfd_siginfo = unsafe { mem::zeroed() };
                while unsafe {
                    libc::read(winch_sfd, &mut si as *mut _ as *mut libc::c_void, mem::size_of::<libc::signalfd_siginfo>())
                } == mem::size_of::<libc::signalfd_siginfo>() as isize {
                    let mut nws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
                    unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut nws) };
                    let mut wd2 = [0u8; 4];
                    wd2[0..2].copy_from_slice(&nws.ws_row.to_be_bytes());
                    wd2[2..4].copy_from_slice(&nws.ws_col.to_be_bytes());
                    let _ = send_frame(sock, MSG_WINCH, &wd2);
                }
            } else if fd == libc::STDIN_FILENO {
                let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    if send_frame(sock, MSG_OUT, &buf[..n as usize]).is_err() {
                        break 'outer;
                    }
                } else {
                    break 'outer;
                }
            } else if fd == sock {
                if events[i as usize].events & libc::EPOLLIN as u32 != 0 {
                    // 一次性把当前已到达的帧都消费掉，避免多余的 poll() 探测
                    loop {
                        let (typ, mlen) = match recv_frame_hdr(sock) {
                            Ok(v) => v,
                            Err(_) => break 'outer,
                        };

                        if typ == MSG_EXIT {
                            let mut nc = [0u8; 4];
                            if mlen >= 4 {
                                let _ = read_exact(sock, &mut nc);
                            }
                            exit_code = i32::from_be_bytes(nc);
                            break 'outer;
                        }

                        let mut rem = mlen as usize;
                        let mut io_err = false;
                        while rem > 0 {
                            let c = rem.min(buf.len());
                            if read_exact(sock, &mut buf[..c]).is_err() {
                                io_err = true;
                                break;
                            }
                            let out_fd = if typ == MSG_ERR { libc::STDERR_FILENO } else { libc::STDOUT_FILENO };
                            unsafe { libc::write(out_fd, buf.as_ptr() as *const libc::c_void, c) };
                            rem -= c;
                        }
                        if io_err {
                            break 'outer;
                        }

                        // 不阻塞地检查 sock 上是否还有更多数据
                        let mut pfd = libc::pollfd { fd: sock, events: libc::POLLIN, revents: 0 };
                        let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if pr <= 0 || pfd.revents & libc::POLLIN == 0 {
                            break;
                        }
                    }
                }
                if events[i as usize].events & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0 {
                    break 'outer;
                }
            }
        }
    }

    if raw_tty_active {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &orig) };
        if winch_sfd >= 0 {
            let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGWINCH);
                libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut());
            }
            unsafe { libc::close(winch_sfd) };
        }
    }
    if epfd >= 0 { unsafe { libc::close(epfd) }; }
    unsafe { libc::close(sock) };
    exit_code
}

// ── Public API ──

pub fn daemon_run(foreground: bool) -> i32 {
    crate::pid::ensure_runtime().ok();
    if daemon_probe() { log_error!("Daemon is already running (@{})", constants::PROJECT_NAME); return 1; }
    daemonize(foreground);
    if let Ok(path) = std::fs::read_link("/proc/self/exe") { *G_SELF_PATH.lock().unwrap() = path.to_string_lossy().to_string(); }
    let srv = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if srv < 0 { log_error!("daemon: socket: {}", io::Error::last_os_error()); return 1; }
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let alen = make_addr(&mut addr);
    if unsafe { libc::bind(srv, &addr as *const libc::sockaddr_un as *const libc::sockaddr, alen) } < 0 {
        log_error!("daemon: bind(@{}): {}", constants::PROJECT_NAME, io::Error::last_os_error()); unsafe { libc::close(srv) }; return 1;
    }
    if unsafe { libc::listen(srv, libc::SOMAXCONN) } < 0 { log_error!("daemon: listen: {}", io::Error::last_os_error()); unsafe { libc::close(srv) }; return 1; }
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN); libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    log_info!("Listening on @{} (PID {})", constants::PROJECT_NAME, unsafe { libc::getpid() });
    loop {
        let conn = unsafe { libc::accept4(srv, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if conn < 0 { if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; } break; }

        // 鉴权对端：只允许 uid 0（root）连接。abstract socket 没有文件系统
        // 权限保护，任何本地进程都能按名字连上来——这个检查不能省略，否则
        // 任何 uid 的进程都可以让以 root 运行的 daemon 执行任意 asc 命令，
        // 等同于本地提权。对应原 daemon.c 里 accept 循环中的 SO_PEERCRED 校验。
        let mut cred: libc::ucred = unsafe { mem::zeroed() };
        let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let got_cred = unsafe {
            libc::getsockopt(
                conn,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut clen,
            )
        } == 0;
        if !got_cred {
            unsafe { libc::close(conn) };
            continue;
        }
        if cred.uid != 0 {
            let msg = b"permission denied: only user 0 may connect.\n";
            let _ = send_frame(conn, MSG_ERR, msg);
            send_exit(conn, 1);
            unsafe { libc::close(conn) };
            continue;
        }

        let child = unsafe { libc::fork() };
        if child == 0 { unsafe { libc::close(srv) }; handle_conn(conn); }
        unsafe { libc::close(conn) };
    }
    1
}

pub fn daemon_probe() -> bool {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 { return false; }
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let alen = make_addr(&mut addr);
    let result = unsafe { libc::connect(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, alen) } == 0;
    unsafe { libc::close(fd) };
    result
}
