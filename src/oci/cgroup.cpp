#include "asc.h"

/**
 * 移植自 LXC 的 Cgroup 设置逻辑：
 * 1. 从 /proc/self/mountinfo 发现宿主机的结构。
 * 2. 如果 Cgroup 命名空间存在 (Linux 4.6+)，直接挂载对应的架构。
 * 3. 否则 (旧版内核)，从宿主机绑定挂载容器的子集。
 */

bool cgroup_host_is_v2(void) {
  auto_fclose FILE *f = fopen("/proc/self/mountinfo", "re");
  if (!f)
    return false;

  char line[2048];
  while (fgets(line, sizeof(line), f)) {
    char *dash = strstr(line, " - ");
    if (!dash)
      continue;

    char fstype[16];
    if (sscanf(dash + 3, "%15s", fstype) != 1)
      continue;
    if (strcmp(fstype, "cgroup2") != 0)
      continue;

    char *p = line;
    for (int i = 0; i < 4; i++) {
      p = strchr(p, ' ');
      if (!p)
        break;
      p++;
    }
    if (!p)
      continue;

    char *mp_end = strchr(p, ' ');
    if (!mp_end)
      continue;
    *mp_end = '\0';

    if (strstr(p, "/" PROJECT_NAME "/"))
      continue;

    return true;
  }

  return false;
}

static bool cgroup_kernel_supports_v2(void) {
  return grep_file("/proc/filesystems", "cgroup2");
}

void cgroup_host_bootstrap(const bool force_cgroupv1) {
  struct statfs sfs;
  if (force_cgroupv1)
    return;

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type == CGROUP2_SUPER_MAGIC)
    return;

  if (!cgroup_kernel_supports_v2()) {
    log_info("[CGROUP] 系统文件系统不支持 cgroup2，跳过引导初始化。");
    return;
  }

  if (!fs::exists("/sys/fs/cgroup")) {
    if (mkdir_p("/sys/fs/cgroup", 0755) != 0) {
      log_error("[CGROUP] 创建 /sys/fs/cgroup 失败: %s",
                strerror(errno));
      return;
    }
  }

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type != TMPFS_MAGIC &&
      sfs.f_type != CGROUP2_SUPER_MAGIC) {
    if (mount("none", "/sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") != 0) {
      log_error("[CGROUP] 挂载 tmpfs 到 /sys/fs/cgroup 失败: %s",
                strerror(errno));
      return;
    }
    log_info("[CGROUP] 已在 /sys/fs/cgroup 挂载 tmpfs 锚点。");
  }

  if (mount("none", "/sys/fs/cgroup", "cgroup2",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
    log_error("挂载 cgroup2 到 /sys/fs/cgroup 失败: %s", strerror(errno));
    return;
  }
  log_info("自动引导并挂载了 cgroup2 到 /sys/fs/cgroup。");
}

static void mount_v1_controllers(void) {
  auto_fclose FILE *f = fopen("/proc/cgroups", "re");
  if (!f)
    return;

  constexpr unsigned long flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
  char line[256];
  if (!fgets(line, sizeof(line), f)) {
    return;
  }

  while (fgets(line, sizeof(line), f)) {
    char name[64];
    int hier, ncg, enabled;
    if (sscanf(line, "%63s %d %d %d", name, &hier, &ncg, &enabled) != 4)
      continue;
    if (!enabled)
      continue;

    fs::path mp = fs::path("sys/fs/cgroup") / name;
    if (fs::exists(mp))
      continue;

    if (mkdir(mp.c_str(), 0755) < 0 && errno != EEXIST)
      continue;

    if (mount("cgroup", mp.c_str(), "cgroup", flags, name) != 0) {
      log_info("[CGROUP] v1 控制器 '%s' 不可用: %s", name,
               strerror(errno));
      fs::remove(mp);
    } else {
      log_info("[CGROUP] 成功挂载 v1 控制器: %s", name);
    }
  }
}

int setup_cgroups(const bool force_cgroupv1) {
  cgroup_host_bootstrap(force_cgroupv1);

  if (!fs::exists("sys/fs/cgroup")) {
    if (mkdir_p("sys/fs/cgroup", 0755) < 0)
      return -1;
  }

  if (domount("none", "sys/fs/cgroup", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755,size=16M") < 0)
    return -1;

  const bool v2_active = cgroup_host_is_v2() && !force_cgroupv1;
  bool systemd_setup_done = false;

  if (v2_active) {
    if (mount("cgroup2", "sys/fs/cgroup", "cgroup2",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) == 0) {
      systemd_setup_done = true;
    } else {
      log_error("挂载 cgroup2 失败: %s", strerror(errno));
    }
  } else {
    mount_v1_controllers();

    if (!fs::exists("sys/fs/cgroup/systemd")) {
      mkdir("sys/fs/cgroup/systemd", 0755);
      if (mount("cgroup", "sys/fs/cgroup/systemd", "cgroup",
                MS_NOSUID | MS_NODEV | MS_NOEXEC, "none,name=systemd") < 0) {
        log_error("挂载 systemd (v1) cgroup 失败: %s", strerror(errno));
        return -1;
      }
    }
    systemd_setup_done = true;
  }

  if (!systemd_setup_done) {
    log_error("Cgroup 配置失败。依赖 Systemd 的容器将无法启动。");
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
    if (auto content = read_file_cpp(events_path.c_str())) {
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
  auto_closedir DIR *d = opendir("/sys/fs/cgroup");
  if (!d)
    return;

  struct dirent *de;
  while ((de = readdir(d)) != nullptr) {
    if (de->d_name[0] == '.')
      continue;

    auto base = fs::path("/sys/fs/cgroup");
    fs::path cg_path;
    if (de->d_name == std::string("cgroup.procs")) {
      cg_path = base / "asc" / container_name;
    } else {
      cg_path = base / de->d_name / "asc" / container_name;
    }

    if (!fs::exists(cg_path))
      continue;
    rmdir_cgroup_tree(cg_path.c_str());
    if (strcmp(de->d_name, "cgroup.procs") == 0)
      break;
  }
}

void print_cgroup_status(const cfg_t *cfg) {
  const bool limits_set = cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit;

  if (cfg->conf.force_cgroupv1) {
    log_warn("正在使用传统的 Cgroup V1 架构 (由于启用了 force-cgroupv1)");
    if (limits_set) {
      log_warn("资源限制 (memory/cpus/pids-limit) 需要 Cgroup V2 的支持，"
               "在当前模式下将不会生效。");
    }
    return;
  }

  const bool host_supports_v2 = cgroup_kernel_supports_v2();

  if (!host_supports_v2) {
    log_warn("宿主机内核不支持 Cgroup V2 (自动回退至 V1 架构)");
    if (limits_set) {
      log_warn(
          "[CGROUP] 资源限制 (memory/cpus/pids-limit) 需要 Cgroup V2 的支持，"
          "在当前宿主机上将不会生效。");
    }
  }
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

static bool ctrl_supported_v2(const char *cg_path, const char *name) {
  if (strlen(cg_path) > PATH_MAX - 32)
    return false;
  fs::path path = fs::path(cg_path) / "cgroup.controllers";
  auto content = read_file_cpp(path.c_str());
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

  if (cfg->conf.force_cgroupv1 || !cgroup_host_is_v2()) {
    cfg->conf.memory_limit = 0;
    cfg->conf.cpu_quota = 0;
    cfg->conf.pids_limit = 0;
    return 0;
  }

  int err = 0;

  fs::path cg = fs::path("/sys/fs/cgroup/asc") / cfg->rt.container_name;
  if (!fs::exists(cg)) {
    log_warn("[CGROUP] 未找到容器的专属子组，跳过资源限制应用。");
    return -1;
  }

  if (cfg->conf.memory_limit) {
    if (ctrl_supported_v2(cg.c_str(), "memory")) {
      fs::path cg_memory_path = cg / "memory.max";
      if (write_file(cg_memory_path.c_str(), std::to_string(cfg->conf.memory_limit).c_str()) < 0) {
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
    if (ctrl_supported_v2(cg.c_str(), "cpu")) {
      const long long period = cfg->conf.cpu_period > 0 ? cfg->conf.cpu_period : 100000;
      fs::path cg_cpu_path = cg / "cpu.max";
      if (write_file(cg_cpu_path.c_str(), std::format("{} {}", cfg->conf.cpu_quota, period).c_str()) < 0) {
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
    if (ctrl_supported_v2(cg.c_str(), "pids")) {
      fs::path cg_pids_path = cg / "pids.max";
      if (write_file(cg_pids_path.c_str(), std::to_string(cfg->conf.pids_limit).c_str()) < 0) {
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

  if (cgroup_host_is_v2()) {
    fs::path cg = fs::path("/sys/fs/cgroup/asc") / container_name;
    if (!fs::exists(cg))
      return -1;
    if (mem) {
      fs::path path = cg / "memory.current";
      if (auto content = read_file_cpp(path.c_str()))
        *mem = parse_cgroup_ll(content->c_str());
    }
    if (cpu_us) {
      fs::path path = cg / "cpu.stat";
      if (auto content = read_file_cpp(path.c_str())) {
        const char *p = strstr(content->c_str(), "usage_usec ");
        if (p)
          *cpu_us = parse_cgroup_ll(p + 11);
      }
    }
    if (pids) {
      fs::path path = cg / "pids.current";
      if (auto content = read_file_cpp(path.c_str()))
        *pids = parse_cgroup_ll(content->c_str());
    }
  }
  return 0;
}