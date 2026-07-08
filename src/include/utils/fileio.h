#ifndef ASC_UTILS_FILEIO_H
#define ASC_UTILS_FILEIO_H

#include "common.h"

int mkdir_p(const fs::path& path, mode_t mode);
int write_file(const char *path, const char *content);
ssize_t write_all(const int fd, const void *buf, const size_t count);
int read_file(const char *path, char *buf, const size_t size);
int remove_recursive(const fs::path& path);
bool grep_file(const fs::path& path, std::string_view pattern);
bool path_has_symlink(const fs::path& path);
int force_unlink(const char *path);
int safe_openat_proc(const pid_t pid, const char *subpath, const int flags, const mode_t mode);

#endif
