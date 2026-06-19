/*
 * ds-fork v6 - Resource Visibility Virtualization
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Zero-dependency LXCFS alternative. Virtualizes /proc/meminfo,
 * /proc/cpuinfo, /proc/stat, /proc/uptime, /proc/loadavg, and
 * /sys/devices/system/cpu/{online,possible,present} based on active
 * cgroup v2 resource limits. Only active limiters incur overhead.
 */

#ifndef VIRTUALIZE_H
#define VIRTUALIZE_H

#include "asc.h"

/* Initialize virtual proc in container rootfs (called inside container,
 * pre-exec). Creates tmpfs at /run/ds-fork/vproc, writes and bind-mounts
 * only the proc/sysfs files relevant to active limits. No-op if no limits set.
 */
int virtualize_init(struct config *cfg);

/* Update dynamic virtual files from monitor process every 500ms.
 * Writes in-place to preserve bind-mount inodes. Guards against PID recycling
 * via ns_inode check. Always runs for uptime/loadavg regardless of limits.
 * Uptime derived from container init PID's /proc/<pid>/stat starttime and
 * CLOCK_BOOTTIME (lxcfs-style), not from host /proc/uptime. */
void virtualize_update(struct config *cfg);

/* Return PID namespace inode for identity verification. Returns 0 on error. */
unsigned long get_pid_ns_inode(pid_t pid);

#endif /* VIRTUALIZE_H */
