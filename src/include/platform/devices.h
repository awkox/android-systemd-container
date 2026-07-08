#ifndef ASC_PLATFORM_DEVICES_H
#define ASC_PLATFORM_DEVICES_H

#include "common.h"

int setup_dev(const char *rootfs, const bool hw_access, const bool gpu_mode, const int privileged_mask);
int setup_devpts(const bool hw_access);
int fix_host_ptys(void);

#endif
