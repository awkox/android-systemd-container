#ifndef ASC_UTILS_WORKSPACE_H
#define ASC_UTILS_WORKSPACE_H

#include "common.h"

const char *get_runtime_dir(void);
const char *get_lock_dir(void);
const char *get_logs_dir(void);
int ensure_runtime(void);
void generate_container_name(const char *rootfs_path, char *name, const size_t size);
int count_folders(const char *path);

#endif
