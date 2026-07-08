#ifndef ASC_PLATFORM_NETLINK_H
#define ASC_PLATFORM_NETLINK_H

#include "common.h"

nl_ctx_t *nl_open();
int nl_link_up(nl_ctx_t *ctx, const char *ifname);

#endif
