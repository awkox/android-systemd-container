#ifndef ASC_PLATFORM_MOUNT_H
#define ASC_PLATFORM_MOUNT_H

#include <filesystem>

int mount_rootfs_img(const std::filesystem::path &img_path, const std::filesystem::path &mount_point);
int mask_path(const char *path);

#endif
