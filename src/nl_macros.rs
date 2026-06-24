//! Netlink 辅助宏（内联函数替代 C 的 NLMSG_* 宏）。
//!
//! 这些宏在 libc crate 中不可用（它们是 C 预处理器宏），
//! 必须手动实现为 Rust 函数。

use std::mem;

/// NLMSG 对齐粒度（Linux 内核中固定为 4 字节）
const NLMSG_ALIGNTO: usize = 4;

/// 将长度对齐到 NLMSG_ALIGNTO 边界
#[inline]
fn nlmsg_align(len: u32) -> u32 {
    (len + NLMSG_ALIGNTO as u32 - 1) & !(NLMSG_ALIGNTO as u32 - 1)
}

/// 检查 netlink 消息头指针是否仍在缓冲区范围内。
/// 等价于 C 宏 `NLMSG_OK(nlh, len)`。
///
/// # Safety
/// `nlh` 必须指向有效的 `nlmsghdr` 或为 null；
/// `remaining` 必须是缓冲区剩余字节数的正确表示。
#[inline]
pub unsafe fn nlmsg_ok(nlh: *const libc::nlmsghdr, remaining: u32) -> bool {
    remaining >= mem::size_of::<libc::nlmsghdr>() as u32
        && unsafe { (*nlh).nlmsg_len } >= mem::size_of::<libc::nlmsghdr>() as u32
        && unsafe { (*nlh).nlmsg_len } <= remaining
}

/// 获取下一条 netlink 消息头。
/// 等价于 C 宏 `NLMSG_NEXT(nlh, len)`。
///
/// # Safety
/// `nlh` 必须指向有效的 `nlmsghdr`。
/// `remaining` 会被更新为剩余的字节数。
#[inline]
pub unsafe fn nlmsg_next(nlh: *const libc::nlmsghdr, remaining: &mut usize) -> *const libc::nlmsghdr {
    let len = unsafe { (*nlh).nlmsg_len } as usize;
    let aligned = (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1);
    *remaining = remaining.saturating_sub(aligned);
    unsafe { (nlh as *const u8).add(aligned) as *const libc::nlmsghdr }
}

/// 获取 netlink 消息的数据部分。
/// 等价于 C 宏 `NLMSG_DATA(nlh)`。
///
/// # Safety
/// `nlh` 必须指向有效的 `nlmsghdr`，返回的指针在消息有效期内有效。
#[inline]
pub unsafe fn nlmsg_data(nlh: *mut libc::nlmsghdr) -> *mut libc::c_void {
    unsafe { (nlh as *mut u8).add(mem::size_of::<libc::nlmsghdr>()) as *mut libc::c_void }
}

/// 计算指定 payload 长度所需的 netlink 消息总长度。
/// 等价于 C 宏 `NLMSG_LENGTH(payload_len)`。
#[inline]
pub fn nlmsg_length(payload_len: u32) -> u32 {
    nlmsg_align(mem::size_of::<libc::nlmsghdr>() as u32) + nlmsg_align(payload_len)
}

