#ifndef ASC_PLATFORM_DEVICES_H
#define ASC_PLATFORM_DEVICES_H

int setup_dev(const char *rootfs);
int setup_devpts();
int fix_host_ptys();

#endif
