#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>

#include "utils/fileio.h"

bool create_directories_with_permission(const std::filesystem::path &target,
                                        mode_t mode) {
  // 规范化路径（解析掉多余的 / 以及 . 或 ..）
  std::filesystem::path normalized_target = target.lexically_normal();
  std::filesystem::path current;

  for (const auto &component : normalized_target) {
    current /= component;

    // 如果当前层级路径不存在，则尝试创建
    if (std::error_code ec; !std::filesystem::exists(current)) {
      // 调用底层 mkdir。注意：此时生成的实际权限是 (mode & ~umask)
      if (mkdir(current.c_str(), mode) != 0) {
        // 处理并发场景：如果另一个线程/进程刚刚创建了它，报 EEXIST 是正常的
        if (errno != EEXIST) {
          return false;
        }
      }
    } else {
      // 如果路径已存在，检查它是否真的是一个目录，防止被同名文件占位
      if (!std::filesystem::is_directory(current)) {
        return false;
      }
    }
  }

  return true;
}

int write_file(const std::filesystem::path &path, std::string_view content) {
  std::ofstream out(path, std::ios::binary);
  if (!out)
    return -1;
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

bool grep_file(const std::filesystem::path &path, std::string_view pattern) {
  std::ifstream file(path);
  std::string line;
  while (std::getline(file, line)) {
    if (line.find(pattern) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool path_has_symlink(const std::filesystem::path &path) {
  std::error_code ec;
  std::filesystem::path current;
  for (const auto &part : path) {
    current /= part;
    if (std::filesystem::is_symlink(current, ec)) {
      return true;
    }
  }
  return false;
}
