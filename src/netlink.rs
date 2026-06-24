//! 最小 RTNETLINK 客户端 —— 对应原 netlink.c。
//!
//! 仅实现 link up 操作，用于 NET_NONE 模式下的 loopback 配置。
//!
//! 内核兼容性：3.10+（Android & Linux）。
//! NLMSG_* 宏在 `nl_macros` 模块中实现为内联函数。

use std::ffi::CString;
use std::io;
use std::mem;

use crate::nl_macros;
use crate::types::NlCtx;

/// Netlink 接收缓冲区大小
const NL_BUFSIZE: usize = 8192;

// ══════════════════════════════════════════════════════════════════════════════
// 上下文生命周期
// ══════════════════════════════════════════════════════════════════════════════

/// 打开并绑定 AF_NETLINK / NETLINK_ROUTE socket。
pub fn nl_open() -> io::Result<NlCtx> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    if unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let pid = unsafe { libc::getpid() };

    Ok(NlCtx {
        fd,
        seq: 1,
        pid: pid as u32,
    })
}

/// 关闭 netlink socket 上下文。
pub fn nl_close(ctx: NlCtx) {
    unsafe { libc::close(ctx.fd) };
}

// ══════════════════════════════════════════════════════════════════════════════
// Netlink 通信
// ══════════════════════════════════════════════════════════════════════════════

/// 发送 + 阻塞接收，带完整的多部分/ACK 循环。
///
/// 返回 0 表示成功，负的 errno 表示错误。
unsafe fn nl_talk(ctx: &mut NlCtx, req: *mut libc::nlmsghdr) -> i32 {
    let req_ref = unsafe { &mut *req };
    ctx.seq = ctx.seq.wrapping_add(1);
    req_ref.nlmsg_seq = ctx.seq;
    req_ref.nlmsg_pid = ctx.pid;

    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    let iov = libc::iovec {
        iov_base: req as *mut libc::c_void,
        iov_len: req_ref.nlmsg_len as usize,
    };

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut sa as *mut libc::sockaddr_nl as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as u32;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;

    if unsafe { libc::sendmsg(ctx.fd, &msg, 0) } < 0 {
        return -(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }

    let mut buf = [0u8; NL_BUFSIZE];
    loop {
        let n = unsafe { libc::recv(ctx.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return -(err.raw_os_error().unwrap_or(libc::EIO));
        }

        let mut remaining = n as usize;
        let mut h_ptr = buf.as_ptr() as *const libc::nlmsghdr;

        while unsafe { nl_macros::nlmsg_ok(h_ptr, remaining as u32) } {
            let h = unsafe { &*h_ptr };

            if h.nlmsg_seq != req_ref.nlmsg_seq {
                h_ptr = unsafe { nl_macros::nlmsg_next(h_ptr, &mut remaining) };
                continue;
            }

            if h.nlmsg_type == libc::NLMSG_ERROR as u16 {
                let err_ptr =
                    unsafe { nl_macros::nlmsg_data(h_ptr as *mut libc::nlmsghdr) }
                        as *const libc::nlmsgerr;
                let err = unsafe { &*err_ptr };
                return err.error;
            }

            if h.nlmsg_type == libc::NLMSG_DONE as u16 {
                return 0;
            }

            if (h.nlmsg_flags & libc::NLM_F_MULTI as u16) != 0 {
                h_ptr = unsafe { nl_macros::nlmsg_next(h_ptr, &mut remaining) };
                continue;
            }
            return 0;
        }
        break;
    }
    0
}

// ══════════════════════════════════════════════════════════════════════════════
// 接口索引
// ══════════════════════════════════════════════════════════════════════════════

/// 通过接口名称获取接口索引。
/// 使用 `if_nametoindex`（一个 ioctl，无需 netlink 往返）。
pub fn nl_get_ifindex(ifname: &str) -> i32 {
    let c_name = match CString::new(ifname) {
        Ok(c) => c,
        Err(_) => return -libc::ENODEV,
    };

    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx > 0 {
        idx as i32
    } else {
        -libc::ENODEV
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Link Up
// ══════════════════════════════════════════════════════════════════════════════

/// 将接口设为 UP 状态。发送 RTM_NEWLINK 消息，IFF_UP 标志。
pub fn nl_link_up(ctx: &mut NlCtx, ifname: &str) -> io::Result<()> {
    let idx = nl_get_ifindex(ifname);
    if idx <= 0 {
        return Err(io::Error::from_raw_os_error(libc::ENODEV));
    }

    #[repr(C)]
    struct LinkReq {
        n: libc::nlmsghdr,
        i: libc::ifinfomsg,
    }

    let mut req: LinkReq = unsafe { mem::zeroed() };
    req.n.nlmsg_len = nl_macros::nlmsg_length(mem::size_of::<libc::ifinfomsg>() as u32);
    req.n.nlmsg_type = libc::RTM_NEWLINK;
    req.n.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    req.i.ifi_family = libc::AF_UNSPEC as u8;
    req.i.ifi_index = idx;
    req.i.ifi_flags = libc::IFF_UP as u32;
    req.i.ifi_change = libc::IFF_UP as u32;

    let ret = unsafe { nl_talk(ctx, &mut req.n as *mut libc::nlmsghdr) };
    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret))
    } else {
        Ok(())
    }
}
