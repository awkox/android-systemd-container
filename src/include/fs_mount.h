#ifndef ASC_FS_MOUNT_H
#define ASC_FS_MOUNT_H

#include "common.h"

int mount_rootfs_img(const fs::path &img_path, const fs::path &mount_point);
int mask_path(const char *path);
int nullify_path(const char *path);

#endif
