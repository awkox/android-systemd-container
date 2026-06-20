/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Minimal RTNETLINK client: link up/down operations.
 * Used by NET_NONE mode for loopback configuration.
 *
 * Kernel compatibility: 3.10+ (Android & Linux)
 * No external dependencies beyond musl/glibc.
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* ---------------------------------------------------------------------------
 * Internal constants
 * ---------------------------------------------------------------------------*/

#define NL_BUFSIZE 8192

/* ---------------------------------------------------------------------------
 * Context lifecycle
 * ---------------------------------------------------------------------------*/

struct nl_ctx {
  int fd;       /* AF_NETLINK / NETLINK_ROUTE socket */
  uint32_t seq; /* monotonically increasing sequence number */
  pid_t pid;    /* our PID used as nl_portid */
};

nl_ctx_t *nl_open(void) {
  nl_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;

  ctx->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (ctx->fd < 0) {
    free(ctx);
    return NULL;
  }

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (bind(ctx->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(ctx->fd);
    free(ctx);
    return NULL;
  }

  ctx->pid = getpid();
  ctx->seq = 1;
  return ctx;
}

void nl_close(nl_ctx_t *ctx) {
  if (ctx) {
    close(ctx->fd);
    free(ctx);
  }
}

/* ---------------------------------------------------------------------------
 * Send + blocking receive with full multi-part / ACK loop
 *
 * Returns 0 on success, negative errno on error.
 * NLMSG_ERROR with error==0 is an explicit ACK (success).
 * ---------------------------------------------------------------------------*/

static int nl_talk(nl_ctx_t *ctx, struct nlmsghdr *req) {
  req->nlmsg_seq = ++ctx->seq;
  req->nlmsg_pid = (uint32_t)ctx->pid;

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  struct iovec iov = {req, req->nlmsg_len};
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
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

    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    for (; NLMSG_OK(h, (uint32_t)n); h = NLMSG_NEXT(h, n)) {
      /* Ignore responses for other in-flight requests */
      if (h->nlmsg_seq != req->nlmsg_seq)
        continue;

      if (h->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = NLMSG_DATA(h);
        return err->error; /* 0 = ACK/success, negative = error */
      }
      if (h->nlmsg_type == NLMSG_DONE)
        return 0;
      if (h->nlmsg_flags & NLM_F_MULTI)
        continue; /* more fragments coming */
      return 0;
    }
    break;
  }
  return 0;
}

/* ---------------------------------------------------------------------------
 * Get interface index by name
 * (uses if_nametoindex - one ioctl, no netlink round-trip needed)
 * ---------------------------------------------------------------------------*/

int nl_get_ifindex(const char *ifname) {
  unsigned int idx = if_nametoindex(ifname);
  return (idx > 0) ? (int)idx : -ENODEV;
}

/* ---------------------------------------------------------------------------
 * Bring link UP
 * ---------------------------------------------------------------------------*/

int nl_link_up(nl_ctx_t *ctx, const char *ifname) {
  int idx = nl_get_ifindex(ifname);
  if (idx <= 0)
    return -ENODEV;

  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req;
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_type = RTM_NEWLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = idx;
  req.i.ifi_flags = IFF_UP;
  req.i.ifi_change = IFF_UP;
  return nl_talk(ctx, &req.n);
}
