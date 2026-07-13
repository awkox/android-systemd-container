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

int write_file(const fs::path& path, std::string_view content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return -1;
    out << content;
    return out.good() ? 0 : -1;
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
