#ifndef ASC_PLATFORM_BLOCKDEV_H
#define ASC_PLATFORM_BLOCKDEV_H

const char *detect_fs_type(const fs::path& img_path);
int loop_attach(const fs::path& img_path, char *loop_path_out, const size_t path_size);

#endif