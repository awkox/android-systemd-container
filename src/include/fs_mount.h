#ifndef ASC_FS_MOUNT_H
#define ASC_FS_MOUNT_H

#include "common.h"

bool is_mountpoint(const fs::path& path);
int domount(const char *src, const char *tgt, const char *fstype, const unsigned long flags, const char *data);
int bind_mount(const fs::path& src, const fs::path& tgt);
int mount_rootfs_img(const char *img_path, char *mount_point, const size_t mp_size, const char *name);
void unmount_rootfs_img(const char *mount_point, const bool silent);

#endif
