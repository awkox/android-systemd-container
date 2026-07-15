#ifndef ASC_PLATFORM_BLOCKDEV_H
#define ASC_PLATFORM_BLOCKDEV_H

int loop_attach(const fs::path& img_path, fs::path& loop_path_out);

#endif
