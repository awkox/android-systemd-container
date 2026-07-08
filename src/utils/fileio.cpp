#include "asc.h"

int mkdir_p(const fs::path& path, mode_t mode) {
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec && ec.value() != EEXIST) {
        errno = ec.value();
        return -1;
    }
    fs::permissions(path, static_cast<fs::perms>(mode),
                    fs::perm_options::replace, ec);
    return 0;
}

int write_file(const char *path, const char *content) {
  const int fd =
    open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  const size_t len = strlen(content);
  const ssize_t w = write_all(fd, content, len);
  const int close_ret = close(fd);

  return w == static_cast<ssize_t>(len) && close_ret == 0 ? 0 : -1;
}

ssize_t write_all(const int fd, const void *buf, const size_t count) {
  const char *p = static_cast<const char *>(buf);
  size_t remaining = count;
  while (remaining > 0) {
    const ssize_t w = write(fd, p, remaining);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += w;
    remaining -= static_cast<size_t>(w);
  }
  return static_cast<ssize_t>(count);
}

int read_file(const char *path, char *buf, const size_t size) {
  if (size == 0)
    return -1;

  auto_close const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;

  ssize_t total_read = 0;
  ssize_t r = 1;
  while (static_cast<size_t>(total_read) < size - 1 &&
         (r = read(fd, buf + total_read, size - 1 - static_cast<size_t>(total_read))) > 0) {
    total_read += r;
  }

  if (r < 0)
    return -1;

  buf[total_read] = '\0';

  while (total_read > 0 &&
         (buf[total_read - 1] == '\n' || buf[total_read - 1] == '\r')) {
    buf[--total_read] = '\0';
  }

  return static_cast<int>(total_read);
}

int remove_recursive(const fs::path& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
    if (ec) {
        errno = ec.value();
        return -1;
    }
    return 0;
}

bool grep_file(const fs::path& path, std::string_view pattern) {
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        if (line.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool path_has_symlink(const fs::path& path) {
    std::error_code ec;
    fs::path current;
    for (const auto& part : path) {
        current /= part;
        if (fs::is_symlink(current, ec)) {
            return true;
        }
    }
    return false;
}

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

int safe_openat_proc(const pid_t pid, const char *subpath, const int flags, const mode_t mode) {
  if (pid <= 0 || !subpath || subpath[0] == '\0')
    return -1;

  char root[64];
  snprintf(root, sizeof(root), "/proc/%d/root", pid);
  auto_close int dirfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0)
    return -1;

  char tmp[PATH_MAX];
  safe_strncpy(tmp, subpath, sizeof(tmp));

  char *save = nullptr;
  const char *comp = strtok_r(tmp, "/", &save);
  const char *next = strtok_r(nullptr, "/", &save);

  while (comp && next) {
    const int nextfd =
        openat(dirfd, comp, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    if (nextfd < 0)
      return -1;
    close(dirfd);
    dirfd = nextfd;
    comp = next;
    next = strtok_r(nullptr, "/", &save);
  }

  int fd = -1;
  if (comp)
    fd = openat(dirfd, comp, flags | O_NOFOLLOW | O_CLOEXEC, mode);

  return fd;
}