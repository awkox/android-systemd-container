#include "asc.h"

static bool cgroup_kernel_supports_v2(void) {
  return grep_file("/proc/filesystems", "cgroup2");
}

// 处理系统cgroup
int cgroup_host_bootstrap() {
  struct statfs sfs;

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type == CGROUP2_SUPER_MAGIC)
    return 0;

  if (!cgroup_kernel_supports_v2()) {
    log_error("[CGROUP] 系统不支持 cgroup2。本项目已强制要求 Cgroup V2 环境，无法启动。");
    return -1;
  }

  if (!fs::exists("/sys/fs/cgroup")) {
    if (!create_directories_with_permission("sys/fs/cgroup")) {
      log_error("[CGROUP] 创建 sys/fs/cgroup 失败: %s",
                strerror(errno));
      return -1;
    }
  }

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type != TMPFS_MAGIC &&
      sfs.f_type != CGROUP2_SUPER_MAGIC) {
    if (mount("none", "/sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") != 0) {
      log_error("[CGROUP] 挂载 tmpfs 到 /sys/fs/cgroup 失败: %s",
                strerror(errno));
      return -1;
    }
    log_info("[CGROUP] 已在 /sys/fs/cgroup 挂载 tmpfs 锚点。");
  }

  if (mount("none", "/sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
    log_error("挂载 cgroup2 到 sys/fs/cgroup 失败: %s", strerror(errno));
    return -1;
  }
  log_info("自动引导并挂载了 cgroup2 到 /sys/fs/cgroup。");
  return 0;
}

int setup_cgroups() {
  // cwd: /mnt/asc/<name>/
  // 处理系统cgroup
  if (cgroup_host_bootstrap() < 0) return -1;

  // 处理容器cgroup
  if (domount("none", "sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") < 0)
    return -1;

  if (mount("cgroup2", "sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) == 0) {
    return 0;
  } else {
    log_error("挂载 cgroup2 失败: %s", strerror(errno));
    return -1;
  }
}

static void rmdir_cgroup_tree(const fs::path& path) {
  std::error_code ec;
  if (!fs::exists(path, ec)) return;

  // 使用 vector 自动管理内存，彻底消灭 malloc/realloc/free
  std::vector<fs::path> subdirs;
  for (const auto& entry : fs::directory_iterator(path, ec)) {
    if (entry.is_directory(ec)) {
      subdirs.push_back(entry.path());
    }
  }

  // 递归删除子目录
  for (const auto& sub : subdirs) {
    rmdir_cgroup_tree(sub);
  }

  fs::path kill_path = path / "cgroup.kill";
  if (access(kill_path.c_str(), W_OK) == 0) {
    auto_close const int kfd = open(kill_path.c_str(), O_WRONLY | O_CLOEXEC);
    if (kfd >= 0) {
      if (write(kfd, "1", 1) < 0) {}
    }
  }

  fs::path events_path = path / "cgroup.events";
  for (int i = 0; i < 50; i++) {
    if (auto content = read_file_cpp(events_path)) {
      if (strstr(content->c_str(), "populated 0"))
        break;
    }
    usleep(10000); 
  }

  // 原有的不断重试 rmdir 逻辑
  for (int attempt = 0; attempt < 10; attempt++) {
    if (rmdir(path.string().c_str()) == 0 || errno == ENOENT) return;
    if (errno != EBUSY) return;
    usleep(20000);
  }
}

void cgroup_cleanup_container(const char *container_name) {
  rmdir_cgroup_tree(project_cgroup_dir / container_name);
}
