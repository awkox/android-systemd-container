#include <unistd.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <cerrno>
#include <cstring>
#include <vector>
#include <thread>
#include <ranges>
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <linux/magic.h>
#include "oci.h"
#include "utils/log.h"
#include "utils/fileio.h"
#include "utils/path.h"

namespace asc::oci {

namespace {

bool cgroup_kernel_supports_v2() {
  return grep_file("/proc/filesystems", "cgroup2");
}

}

// 处理系统cgroup
int cgroup_host_bootstrap() {
  struct statfs sfs;

  if (statfs("/sys/fs/cgroup", &sfs) == 0 && sfs.f_type == CGROUP2_SUPER_MAGIC)
    return 0;

  if (!cgroup_kernel_supports_v2()) {
    log_error("[CGROUP] 系统不支持 cgroup2。本项目已强制要求 Cgroup V2 环境，无法启动。");
    return -1;
  }

  if (!std::filesystem::exists("/sys/fs/cgroup")) {
    if (!create_directories_with_permission("/sys/fs/cgroup")) {
      log_error("[CGROUP] 创建 /sys/fs/cgroup 失败: {}", strerror(errno));
      return -1;
    }
  }

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type != TMPFS_MAGIC &&
      sfs.f_type != CGROUP2_SUPER_MAGIC) {
    if (mount("none", "/sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") != 0) {
      log_error("[CGROUP] 挂载 tmpfs 到 /sys/fs/cgroup 失败: {}", strerror(errno));
      return -1;
    }
    log_info("[CGROUP] 已在 /sys/fs/cgroup 挂载 tmpfs 锚点。");
  }

  if (mount("none", "/sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
    log_error("挂载 cgroup2 到 /sys/fs/cgroup 失败: {}", strerror(errno));
    return -1;
  }
  log_info("自动引导并挂载了 cgroup2 到 /sys/fs/cgroup。");
  return 0;
}

namespace {

void rmdir_cgroup_tree(const std::filesystem::path &path) {
  using namespace std::chrono_literals;

  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return;

  // 使用 vector 自动管理内存，彻底消灭 malloc/realloc/free
  std::vector<std::filesystem::path> subdirs;
  for (const auto &entry : std::filesystem::directory_iterator(path, ec)) {
    if (entry.is_directory(ec)) {
      subdirs.push_back(entry.path());
    }
  }

  // 递归删除子目录
  for (const auto &sub : subdirs) {
    rmdir_cgroup_tree(sub);
  }

  const std::filesystem::path kill_path = path / "cgroup.kill";
  if (access(kill_path.c_str(), W_OK) == 0) {
    if (const int kfd = open(kill_path.c_str(), O_WRONLY | O_CLOEXEC); kfd >= 0) {
      if (write(kfd, "1", 1) < 0) {}
      close(kfd);
    }
  }
  
  const std::filesystem::path events_path = path / "cgroup.events";
  for ([[maybe_unused]] auto _ : std::views::iota(0, 50)) {
    if (grep_file(events_path, "populated 0"))
      break;
    std::this_thread::sleep_for(10ms);
  }

  // 原有的不断重试 rmdir 逻辑
  for ([[maybe_unused]] auto _ : std::views::iota(0, 10)) {
    if (rmdir(path.string().c_str()) == 0 || errno == ENOENT) return;
    if (errno != EBUSY) return;
    std::this_thread::sleep_for(20ms);
  }
}

}

void cgroup_cleanup_container(std::string_view container_name) {
  rmdir_cgroup_tree(project_cgroup_dir / container_name);
}

}
