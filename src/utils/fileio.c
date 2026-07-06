#include "asc.h"

int mkdir_p(const char *path, const mode_t mode) {
  char tmp[PATH_MAX];

  const int r = snprintf(tmp, sizeof(tmp), "%s", path);
  if (r < 0 || (size_t)r >= sizeof(tmp)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  const size_t len = strlen(tmp);
  if (len == 0)
    return 0;
  if (tmp[len - 1] == '/')
    tmp[len - 1] = '\0';

  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -1;
      *p = '/';
    }
  }
  if (mkdir(tmp, mode) < 0 && errno != EEXIST)
    return -1;
  return 0;
}

int write_file(const char *path, const char *content) {
  auto_close const int fd =
    open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  const size_t len = strlen(content);
  const ssize_t w = write_all(fd, content, len);
  const int close_ret = close(fd);

  return w == (ssize_t)len && close_ret == 0 ? 0 : -1;
}

ssize_t write_all(const int fd, const void *buf, const size_t count) {
  const char *p = buf;
  size_t remaining = count;
  while (remaining > 0) {
    const ssize_t w = write(fd, p, remaining);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += w;
    remaining -= (size_t)w;
  }
  return (ssize_t)count;
}

int read_file(const char *path, char *buf, const size_t size) {
  if (size == 0)
    return -1;

  auto_close const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;

  ssize_t total_read = 0;
  ssize_t r = 1;
  while ((size_t)total_read < size - 1 &&
         (r = read(fd, buf + total_read, size - 1 - (size_t)total_read)) > 0) {
    total_read += r;
  }

  if (r < 0)
    return -1;

  buf[total_read] = '\0';

  /* strip trailing newline and carriage return */
  while (total_read > 0 &&
         (buf[total_read - 1] == '\n' || buf[total_read - 1] == '\r')) {
    buf[--total_read] = '\0';
  }

  return (int)total_read;
}

static int remove_recursive_handler(
  const char *fpath,
  const struct stat *sb [[maybe_unused]],
  int tflag [[maybe_unused]],
  struct FTW *ftwbuf [[maybe_unused]]
) {
  const int r = remove(fpath);
  if (r)
    perror(fpath);
  return r;
}

int remove_recursive(const char *path) {
  return nftw(path, remove_recursive_handler, 64, FTW_DEPTH | FTW_PHYS);
}

int grep_file(const char *path, const char *pattern) {
  char buf[16384];
  if (read_file(path, buf, sizeof(buf)) < 0)
    return -1;
  return strstr(buf, pattern) ? 1 : 0;
}

/* Check if any path component (prefix) is a symbolic link.
 * lstat() does not follow the final component, so walking each prefix
 * with lstat() detects symlinks at ANY level — not just the final one.
 * Returns 1 if a symlink is found, 0 otherwise. */
bool path_has_symlink(const char *path) {
  char tmp[PATH_MAX];
  safe_strncpy(tmp, path, sizeof(tmp));
  if (strlen(tmp) == 0)
    return false;

  /* Walk each '/' boundary and lstat the prefix */
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      struct stat st;
      if (lstat(tmp, &st) == 0 && S_ISLNK(st.st_mode)) {
        return true;
      }
      *p = '/';
    }
  }
  /* Check the full path */
  struct stat st;
  if (lstat(tmp, &st) == 0 && S_ISLNK(st.st_mode))
    return true;
  return false;
}

bool is_subpath(const char *parent, const char *child) {
  auto_free char *real_parent = resolve_path_arg(parent);
  auto_free char *real_child = resolve_path_arg(child);

  if (!real_parent || !real_child || !real_parent[0] || !real_child[0])
    return false;

  const size_t len = strlen(real_parent);

  /* Special case for the root directory */
  if (len == 1 && real_parent[0] == '/')
    return true;

  if (strncmp(real_parent, real_child, len) == 0)
    if (real_child[len] == '\0' || real_child[len] == '/')
      return true;

  return false;
}

/* Helper to force removal of a path, even if it is a directory */
int force_unlink(const char *path) {
  if (unlink(path) < 0) {
    if (errno == EISDIR) {
      return rmdir(path);
    }
    if (errno == ENOENT) {
      return 0;
    }
    return -1;
  }
  return 0;
}
