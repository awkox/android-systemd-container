#ifndef ASC_UTILS_FILEIO_H
#define ASC_UTILS_FILEIO_H

#include "common.h"

bool create_directories_with_permission(const fs::path& target, mode_t mode = 0755);
int write_file(fs::path path, const char *content);
ssize_t write_all(const int fd, const void *buf, const size_t count);
std::optional<std::string> read_file_cpp(const fs::path& path);
int remove_recursive(const fs::path& path);
bool grep_file(const fs::path& path, std::string_view pattern);
bool path_has_symlink(const fs::path& path);
int safe_openat_proc(const pid_t pid, fs::path subpath, const int flags, const mode_t mode);

#endif
