#include "asc.h"

/* ---------------------------------------------------------------------------
 * Netlink 上下文生命周期管理
 * ---------------------------------------------------------------------------*/

nl_ctx_t *nl_open(void) {
  nl_ctx_t *ctx = static_cast<nl_ctx_t *>(calloc(1, sizeof(*ctx)));
  if (!ctx)
    return nullptr;

  ctx->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (ctx->fd < 0) {
    free(ctx);
    return nullptr;
  }

  struct sockaddr_nl sa = {};
  sa.nl_family = AF_NETLINK;
  
  if (bind(ctx->fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) < 0) {
    close(ctx->fd);
    free(ctx);
    return nullptr;
  }

  ctx->pid = getpid();
  ctx->seq = 1;
  return ctx;
}

/* ---------------------------------------------------------------------------
 * 发送 + 阻塞接收，并带有完整的 Multi-part/ACK 处理循环
 * 成功返回 0，错误返回负的 errno。
 * NLMSG_ERROR 类型且 error==0 是显式的 ACK。
 * ---------------------------------------------------------------------------*/

static int nl_talk(nl_ctx_t *ctx, struct nlmsghdr *req) {
  req->nlmsg_seq = ++ctx->seq;
  req->nlmsg_pid = static_cast<uint32_t>(ctx->pid);

  struct sockaddr_nl sa = {};
  sa.nl_family = AF_NETLINK;
  
  struct iovec iov = {};
  iov.iov_base = req;
  iov.iov_len = req->nlmsg_len;
  
  struct msghdr msg = {};
  msg.msg_name = &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if (sendmsg(ctx->fd, &msg, 0) < 0)
    return -errno;

  uint8_t buf[NL_BUFSIZE];
  for (;;) {
    ssize_t n = recv(ctx->fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -errno;
    }

    for (auto h = reinterpret_cast<struct nlmsghdr *>(buf); 
         NLMSG_OK(h, static_cast<uint32_t>(n)); 
         h = NLMSG_NEXT(h, n)) {
         
      /* 忽略在此期间飞来的其他请求返回的数据包 */
      if (h->nlmsg_seq != req->nlmsg_seq)
        continue;

      if (h->nlmsg_type == NLMSG_ERROR) {
        const struct nlmsgerr *err = static_cast<const struct nlmsgerr *>(NLMSG_DATA(h));
        return err->error; /* 0 = ACK/成功, 负数 = 错误码 */
      }
      if (h->nlmsg_type == NLMSG_DONE)
        return 0;
      if (h->nlmsg_flags & NLM_F_MULTI)
        continue; /* 还有后续的片段，继续接收 */
      return 0;
    }
    break;
  }
  return 0;
}

/* 通过名称获取网卡接口索引 (只使用一次 ioctl，没有繁重的 netlink 通信) */
static int nl_get_ifindex(const char *ifname) {
  const unsigned int idx = if_nametoindex(ifname);
  return idx > 0 ? static_cast<int>(idx) : -ENODEV;
}

/* 启动网卡 (Link UP) */
int nl_link_up(nl_ctx_t *ctx, const char *ifname) {
  const int idx = nl_get_ifindex(ifname);
  if (idx <= 0)
    return -ENODEV;

  struct req_msg {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req = {};
  
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_type = RTM_NEWLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = idx;
  req.i.ifi_flags = IFF_UP;
  req.i.ifi_change = IFF_UP;
  
  return nl_talk(ctx, &req.n);
}