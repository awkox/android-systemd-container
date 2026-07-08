#ifndef ASC_PLATFORM_VIRTUAL_H
#define ASC_PLATFORM_VIRTUAL_H

#include "common.h"

unsigned long get_pid_ns_inode(const pid_t pid);
int virtualize_init(const cfg_t *cfg);
void virtualize_update(const cfg_t *cfg);

#endif
