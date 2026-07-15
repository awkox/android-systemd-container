#ifndef ASC_UTILS_FILEIO_H
#define ASC_UTILS_FILEIO_H

#include "common.h"

bool create_directories_with_permission(const fs::path& target, mode_t mode = 0755);
int write_file(const fs::path& path, std::string_view content);
ssize_t write_all(const int fd, const void *buf, const size_t count);
bool grep_file(const fs::path& path, std::string_view pattern);
bool path_has_symlink(const fs::path& path);

#endif
