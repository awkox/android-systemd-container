#include <cerrno>
#include <format>
#include <unistd.h>
#include <fcntl.h>
#include "core.h"
#include "utils/log.h"
#include "utils/path.h"
#include "utils/fileio.h"

namespace asc::core {

namespace {

int active_lock_fd = -1;
std::filesystem::path active_lock_path = "";

}

int acquire_external_lock(std::string_view name) {
  if (active_lock_fd >= 0)
    return 0;

  std::filesystem::path lock_path = lock_dir / name;

  const int fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;

  flock fl = {};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;

  if (fcntl(fd, F_SETLK, &fl) == 0) {
    std::string pid_str = std::format("{}\n", getpid());
    if (ftruncate(fd, 0) == 0) {
      write_all(fd, pid_str.c_str(), pid_str.size());
    }

    active_lock_fd = fd;
    active_lock_path = lock_path;
    return 0;
  }

  if (errno == EACCES || errno == EAGAIN) {
    if (fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK) {
      log_warn("无法获取锁: 当前已被进程 {} 持有", fl.l_pid);
    }
  }

  close(fd);
  return -1;
}

void release_external_lock(void) {
  if (active_lock_fd >= 0) {
    close(active_lock_fd);
    if (!active_lock_path.empty()) {
      std::filesystem::remove(active_lock_path);
    }
    active_lock_fd = -1;
    active_lock_path = "";
  }
}

void close_external_lock_fd() {
  if (active_lock_fd >= 0) {
    close(active_lock_fd);
    active_lock_fd = -1;
    active_lock_path = "";
  }
}

bool is_external_lock_active(std::string_view name) {
  return std::filesystem::exists(lock_dir / name);
}

}
