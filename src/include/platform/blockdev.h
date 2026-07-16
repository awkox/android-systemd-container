#ifndef ASC_PLATFORM_BLOCKDEV_H
#define ASC_PLATFORM_BLOCKDEV_H

#include <filesystem>

int loop_attach(const std::filesystem::path &img_path, std::filesystem::path &loop_path_out);

#endif
