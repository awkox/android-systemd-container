//! 前台控制台 I/O 循环 —— 对应原 console.c。
//!
//! 基于 epoll 的 I/O 循环，转发 stdin → PTY master → stdout，
//! 支持非阻塞 PTY I/O 背压、CTRL+ALT+Q 退出检测、signalfd 信号处理。

use std::io;
use std::os::unix::io::RawFd;

use crate::container::stop_rootfs;
use crate::pid::find_container_init_pid;
use crate::terminal::setup_tios;
use crate::utils::set_log_silent;

// ══════════════════════════════════════════════════════════════════════════════
// 挂起写入状态
// ══════════════════════════════════════════════════════════════════════════════

struct PendingWrite {
    fd: RawFd,
    data: [u8; 4096],
    len: usize,
    off: usize,
}

impl PendingWrite {
    fn new() -> Self {
        Self { fd: -1, data: [0; 4096], len: 0, off: 0 }
    }
}

// ══════════════════════════════════════════════════════════════════════════════

pub fn console_monitor_loop(
    master_fd: RawFd,
    monitor_pid: libc::pid_t,
    cfg: &mut crate::types::Config,
) -> i32 {
    // ── signalfd 设置 ──
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        libc::sigaddset(&mut mask, libc::SIGINT);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        libc::sigaddset(&mut mask, libc::SIGWINCH);
    }
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) } < 0 {
        return -1;
    }

    let sfd = unsafe {
        libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC)
    };
    if sfd < 0 { return -1; }

    // ── epoll 设置 ──
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 { unsafe { libc::close(sfd) }; return -1; }

    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };

    ev.events = libc::EPOLLIN as u32;
    ev.u64 = libc::STDIN_FILENO as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, libc::STDIN_FILENO, &mut ev); }

    ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = master_fd as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, master_fd, &mut ev); }

    ev.events = libc::EPOLLIN as u32;
    ev.u64 = sfd as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sfd, &mut ev); }

    // PTY master 设为非阻塞
    let fl = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
    if fl >= 0 {
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
    }

    // 终端设为 raw 模式
    let oldtios = setup_tios(libc::STDIN_FILENO);
    let is_tty = oldtios.is_ok();
    let oldtios = oldtios.unwrap_or_else(|_| unsafe { std::mem::zeroed() });

    // 初始窗口大小同步
    if is_tty {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0 {
            unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
        }
    }

    let mut pending = PendingWrite::new();
    let mut running = true;
    let mut ret = 0;
    let mut exit_detected = false;
    let mut events: [libc::epoll_event; 10] = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];

    while running {
        let nfds = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 10, -1) };
        if nfds < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            ret = -1;
            break;
        }

        for i in 0..nfds {
            let fd = events[i as usize].u64 as RawFd;

            if fd == libc::STDIN_FILENO {
                // 用户输入 → 容器 master
                let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    // CTRL+ALT+Q (\x1b\x11) 退出序列
                    if n >= 2 && buf[0] == 0x1b && buf[1] == 0x11 {
                        if !exit_detected {
                            let bg_pid = unsafe { libc::fork() };
                            if bg_pid == 0 {
                                unsafe { libc::setsid() };
                                set_log_silent(true);
                                stop_rootfs(cfg, false);
                                unsafe { libc::_exit(0) };
                            } else if bg_pid > 0 {
                                exit_detected = true;
                            }
                        }
                        continue;
                    }

                    // 写入 master_fd，处理背压
                    let n_usize = n as usize;
                    if pending.fd < 0 {
                        let w = unsafe { libc::write(master_fd, buf.as_ptr() as *const libc::c_void, n_usize) };
                        if w >= 0 && (w as usize) < n_usize {
                            pending.fd = master_fd;
                            pending.len = n_usize - w as usize;
                            pending.off = 0;
                            pending.data[..pending.len].copy_from_slice(&buf[w as usize..n_usize]);
                            add_epollout(epfd, master_fd);
                        } else if w < 0 {
                            let err = io::Error::last_os_error();
                            if err.raw_os_error() == Some(libc::EAGAIN) {
                                pending.fd = master_fd;
                                pending.len = n_usize;
                                pending.off = 0;
                                pending.data[..pending.len].copy_from_slice(&buf[..n_usize]);
                                add_epollout(epfd, master_fd);
                            } else {
                                running = false;
                                break;
                            }
                        }
                    }
                }
            } else if fd == master_fd {
                if events[i as usize].events & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0 {
                    running = false;
                    break;
                }

                // 排空挂起的写入（EPOLLOUT）
                if events[i as usize].events & libc::EPOLLOUT as u32 != 0 && pending.fd == master_fd {
                    let w = unsafe {
                        libc::write(master_fd,
                            pending.data[pending.off..].as_ptr() as *const libc::c_void,
                            pending.len)
                    };
                    if w > 0 {
                        pending.off += w as usize;
                        pending.len -= w as usize;
                    }
                    if pending.len == 0 || (w < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN)) {
                        pending.fd = -1;
                        del_epollout(epfd, master_fd);
                    }
                }

                // 容器输出 → 用户 stdout（EPOLLIN）
                if events[i as usize].events & libc::EPOLLIN as u32 != 0 {
                    let n = unsafe { libc::read(master_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        unsafe { libc::write(libc::STDOUT_FILENO, buf.as_ptr() as *const libc::c_void, n as usize) };
                    } else {
                        running = false;
                    }
                }
            } else if fd == sfd {
                // 信号处理
                let mut fdsi: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                let n = unsafe {
                    libc::read(sfd, &mut fdsi as *mut libc::signalfd_siginfo as *mut libc::c_void, std::mem::size_of::<libc::signalfd_siginfo>())
                };
                if n != std::mem::size_of::<libc::signalfd_siginfo>() as isize { continue; }

                if fdsi.ssi_signo == libc::SIGCHLD as u32 {
                    let mut status = 0;
                    let child = unsafe { libc::waitpid(monitor_pid, &mut status, libc::WNOHANG) };
                    if child == monitor_pid { running = false; }
                } else if fdsi.ssi_signo == libc::SIGWINCH as u32 {
                    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0 {
                        unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
                    }
                } else if (fdsi.ssi_signo == libc::SIGINT as u32 || fdsi.ssi_signo == libc::SIGTERM as u32)
                    && !cfg.uuid.is_empty() {
                        let live_pid = find_container_init_pid(&cfg.uuid);
                        if live_pid > 0 {
                            unsafe { libc::kill(live_pid, fdsi.ssi_signo as i32) };
                        }
                    }
            }
        }
    }

    // 恢复终端设置
    if is_tty {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &oldtios) };
    }

    unsafe {
        libc::close(epfd);
        libc::close(sfd);
    }
    ret
}

fn add_epollout(epfd: RawFd, fd: RawFd) {
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = fd as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
}

fn del_epollout(epfd: RawFd, fd: RawFd) {
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = fd as u64;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
}
