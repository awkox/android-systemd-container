#include "asc.h"

static bool cgroup_kernel_supports_v2(void) {
  return grep_file("/proc/filesystems", "cgroup2");
}

int cgroup_host_bootstrap() {
  struct statfs sfs;

  if (statfs("sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type == CGROUP2_SUPER_MAGIC)
    return 0;

  if (!cgroup_kernel_supports_v2()) {
    log_error("[CGROUP] 系统不支持 cgroup2。本项目已强制要求 Cgroup V2 环境，无法启动。");
    return -1;
  }

  if (!fs::exists("sys/fs/cgroup")) {
    if (!create_directories_with_permission("sys/fs/cgroup")) {
      log_error("[CGROUP] 创建 sys/fs/cgroup 失败: %s",
                strerror(errno));
      return -1;
    }
  }

  if (statfs("sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type != TMPFS_MAGIC &&
      sfs.f_type != CGROUP2_SUPER_MAGIC) {
    if (mount("none", "sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") != 0) {
      log_error("[CGROUP] 挂载 tmpfs 到 sys/fs/cgroup 失败: %s",
                strerror(errno));
      return -1;
    }
    log_info("[CGROUP] 已在 /sys/fs/cgroup 挂载 tmpfs 锚点。");
  }

  if (mount("none", "sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
    log_error("挂载 cgroup2 到 sys/fs/cgroup 失败: %s", strerror(errno));
    return -1;
  }
  log_info("自动引导并挂载了 cgroup2 到 sys/fs/cgroup。");
  return 0;
}

int setup_cgroups() {
  if (cgroup_host_bootstrap() < 0) return -1;

  if (!fs::exists("sys/fs/cgroup")) {
    if (!create_directories_with_permission("sys/fs/cgroup"))
      return -1;
  }

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

  return 0;
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

static bool ctrl_in_list(const char *list, const char *name) {
  const char *p = list;
  const size_t nlen = strlen(name);
  while (*p) {
    while (*p == ' ' || *p == '\n')
      p++;
    if (strncmp(p, name, nlen) == 0 &&
        (p[nlen] == ' ' || p[nlen] == '\n' || p[nlen] == '\0'))
      return true;
    while (*p && *p != ' ' && *p != '\n')
      p++;
  }
  return false;
}

bool cg_word_in_list(const char *list, const char *name) {
  return ctrl_in_list(list, name);
}

static bool ctrl_supported_v2(const fs::path& cg_path, const char *name) {
  fs::path path = cg_path / "cgroup.controllers";
  auto content = read_file_cpp(path);
  if (!content)
    return false;
  return ctrl_in_list(content->c_str(), name);
}

static long long parse_cgroup_ll(const char *buf) {
  if (strncmp(buf, "max", 3) == 0)
    return -1;
  char *end;
  errno = 0;
  const long long v = strtoll(buf, &end, 10);
  if (errno || end == buf)
    return -1;
  return v;
}

int cgroup_apply_limits(cfg_t *cfg) {
  if (!cfg->conf.memory_limit && !cfg->conf.cpu_quota && !cfg->conf.pids_limit)
    return 0;

  int err = 0;

  fs::path cg = project_cgroup_dir / cfg->rt.container_name;
  if (!fs::exists(cg)) {
    log_warn("[CGROUP] 未找到容器的专属子组，跳过资源限制应用。");
    return -1;
  }

  if (cfg->conf.memory_limit) {
    if (ctrl_supported_v2(cg, "memory")) {
      fs::path cg_memory_path = cg / "memory.max";
      if (write_file(cg_memory_path, std::to_string(cfg->conf.memory_limit).c_str()) < 0) {
        log_warn("[CGROUP] 写入 memory.max 失败: %s", strerror(errno));
        cfg->conf.memory_limit = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 宿主机不支持 'memory' 控制器，跳过内存限制。");
      cfg->conf.memory_limit = 0;
    }
  }
  if (cfg->conf.cpu_quota) {
    if (ctrl_supported_v2(cg, "cpu")) {
      const long long period = cfg->conf.cpu_period > 0 ? cfg->conf.cpu_period : 100000;
      fs::path cg_cpu_path = cg / "cpu.max";
      if (write_file(cg_cpu_path, std::format("{} {}", cfg->conf.cpu_quota, period).c_str()) < 0) {
        log_warn("[CGROUP] 写入 cpu.max 失败: %s", strerror(errno));
        cfg->conf.cpu_quota = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 宿主机不支持 'cpu' 控制器，跳过 CPU 限制。");
      cfg->conf.cpu_quota = 0;
    }
  }
  if (cfg->conf.pids_limit) {
    if (ctrl_supported_v2(cg, "pids")) {
      fs::path cg_pids_path = cg / "pids.max";
      if (write_file(cg_pids_path, std::to_string(cfg->conf.pids_limit).c_str()) < 0) {
        log_warn("[CGROUP] 写入 pids.max 失败: %s", strerror(errno));
        cfg->conf.pids_limit = 0;
        err++;
      }
    } else {
      log_warn("[CGROUP] 宿主机不支持 'pids' 控制器，跳过 PID 限制。");
      cfg->conf.pids_limit = 0;
    }
  }
  return err ? -1 : 0;
}

int cgroup_get_usage(const char *container_name, long long *mem,
                     long long *cpu_us, long long *pids) {
  if (mem)
    *mem = -1;
  if (cpu_us)
    *cpu_us = -1;
  if (pids)
    *pids = -1;

  fs::path cg = project_cgroup_dir / container_name;
  if (!fs::exists(cg))
    return -1;
  if (mem) {
    fs::path path = cg / "memory.current";
    if (auto content = read_file_cpp(path))
      *mem = parse_cgroup_ll(content->c_str());
  }
  if (cpu_us) {
    fs::path path = cg / "cpu.stat";
    if (auto content = read_file_cpp(path)) {
      const char *p = strstr(content->c_str(), "usage_usec ");
      if (p)
        *cpu_us = parse_cgroup_ll(p + 11);
    }
  }
  if (pids) {
    fs::path path = cg / "pids.current";
    if (auto content = read_file_cpp(path))
      *pids = parse_cgroup_ll(content->c_str());
  }
  return 0;
}