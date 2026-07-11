#ifndef ASC_UTILS_SYSTEM_H
#define ASC_UTILS_SYSTEM_H

#include "common.h"

bool is_ramfs(const fs::path& path);
int get_kernel_version(int *major, int *minor);
void oom_protect(void);

#endif
