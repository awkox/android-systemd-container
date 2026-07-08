#ifndef ASC_UTILS_SYSTEM_H
#define ASC_UTILS_SYSTEM_H

#include "common.h"

bool is_ramfs(const char *path);
int parse_os_release(const char *rootfs_path, char *id_out, char *ver_out, const size_t out_size);
int read_proc_environ(const pid_t pid, const char *key, char *value, const size_t size);
int run_command_quiet(char *const argv[]);
int get_kernel_version(int *major, int *minor);
void oom_protect(void);

#endif
