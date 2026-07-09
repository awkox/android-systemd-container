#include "asc.h"

bool create_directories_with_permission(const fs::path& target, mode_t mode) {
  // 规范化路径（解析掉多余的 / 以及 . 或 ..）
  fs::path normalized_target = target.lexically_normal();
  fs::path current;

  for (const auto& component : normalized_target) {
    current /= component;

    std::error_code ec;
    // 如果当前层级路径不存在，则尝试创建
    if (!fs::exists(current, ec)) {
      // 调用底层 mkdir。注意：此时生成的实际权限是 (mode & ~umask)
      if (::mkdir(current.c_str(), mode) != 0) {
        // 处理并发场景：如果另一个线程/进程刚刚创建了它，报 EEXIST 是正常的
        if (errno != EEXIST) {
          return false;
        }
      }
    } else {
      // 如果路径已存在，检查它是否真的是一个目录，防止被同名文件占位
      if (!fs::is_directory(current, ec)) {
        return false;
      }
    }
  }

  return true;
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

std::optional<std::string> read_file_cpp(const fs::path& path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file) return std::nullopt;

    // 利用迭代器一次性读取整个文件
    std::string content((std::istreambuf_iterator<char>(file)), 
                         std::istreambuf_iterator<char>());
    
    // 清理尾部换行符
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
        content.pop_back();
    }
    return content;
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

int safe_openat_proc(const pid_t pid, const char *subpath, const int flags, const mode_t mode) {
  if (pid <= 0)
    return -1;

  fs::path proc_root = proc_dir / std::to_string(pid) / "root";
  auto_close int dirfd = open(proc_root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
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