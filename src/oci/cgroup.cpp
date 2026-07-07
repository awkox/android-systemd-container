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
  return grep_file("/proc/filesystems", "cgroup2") > 0;
}

void cgroup_host_bootstrap(const bool force_cgroupv1) {
  struct statfs sfs;
  if (force_cgroupv1)
    return;

  if (statfs("/sys/fs/cgroup", &sfs) == 0 &&
      sfs.f_type == CGROUP2_SUPER_MAGIC)
    return;

  if (grep_file("/proc/filesystems", "cgroup2") <= 0) {
    log_info("[CGROUP] 系统文件系统不支持 cgroup2，跳过引导初始化。");
    return;
  }

  if (access("/sys/fs/cgroup", F_OK) != 0) {
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

    char mp[PATH_MAX];
    snprintf(mp, sizeof(mp), "sys/fs/cgroup/%s", name);
    if (access(mp, F_OK) == 0)
      continue;

    if (mkdir(mp, 0755) < 0 && errno != EEXIST)
      continue;

    if (mount("cgroup", mp, "cgroup", flags, name) != 0) {
      log_info("[CGROUP] v1 控制器 '%s' 不可用: %s", name,
               strerror(errno));
      rmdir(mp);
    } else {
      log_info("[CGROUP] 成功挂载 v1 控制器: %s", name);
    }
  }
}

int setup_cgroups(const bool force_cgroupv1) {
  cgroup_host_bootstrap(force_cgroupv1);

  if (access("sys/fs/cgroup", F_OK) != 0) {
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

    if (access("sys/fs/cgroup/systemd", F_OK) != 0) {
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

static void rmdir_cgroup_tree(const char *path) {
  auto_closedir DIR *d = opendir(path);
  if (!d) {
    rmdir(path);
    return;
  }

  struct dirent *de;
  while ((de = readdir(d)) != nullptr) {
    if (de->d_name[0] == '.')
      continue;
    if (de->d_type != DT_DIR && de->d_type != DT_UNKNOWN)
      continue;

    char child[PATH_MAX];
    safe_strncpy(child, path, sizeof(child));
    strncat(child, "/", sizeof(child) - strlen(child) - 1);
    strncat(child, de->d_name, sizeof(child) - strlen(child) - 1);
    rmdir_cgroup_tree(child);
  }

  char kill_path[PATH_MAX];
  safe_strncpy(kill_path, path, sizeof(kill_path));
  strncat(kill_path, "/cgroup.kill", sizeof(kill_path) - strlen(kill_path) - 1);
  if (access(kill_path, W_OK) == 0) {
    auto_close const int kfd = open(kill_path, O_WRONLY | O_CLOEXEC);
    if (kfd >= 0) {
      if (write(kfd, "1", 1) < 0) {}
    }
  }

  char events_path[PATH_MAX];
  safe_strncpy(events_path, path, sizeof(events_path));
  strncat(events_path, "/cgroup.events",
          sizeof(events_path) - strlen(events_path) - 1);
  for (int i = 0; i < 50; i++) {
    char buf[256] = "";
    if (read_file(events_path, buf, sizeof(buf)) > 0) {
      if (strstr(buf, "populated 0"))
        break;
    }
    usleep(10000); 
  }

  for (int attempt = 0; attempt < 10; attempt++) {
    if (rmdir(path) == 0 || errno == ENOENT)
      return;
    if (errno != EBUSY)
      return;
    usleep(20000);
  }
}

void cgroup_cleanup_container(const char *container_name) {
  if (!container_name || !container_name[0])
    return;

  char safe_name[256];
  sanitize_container_name(container_name, safe_name, sizeof(safe_name));

  auto_closedir DIR *d = opendir("/sys/fs/cgroup");
  if (!d)
    return;

  struct dirent *de;
  while ((de = readdir(d)) != nullptr) {
    if (de->d_name[0] == '.')
      continue;

    char cg_path[PATH_MAX];
    snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/%s/" PROJECT_NAME "/%s",
             de->d_name, safe_name);

    if (strcmp(de->d_name, "cgroup.procs") == 0)
      snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/" PROJECT_NAME "/%s",
               safe_name);

    if (access(cg_path, F_OK) != 0)
      continue;
    rmdir_cgroup_tree(cg_path);
    if (strcmp(de->d_name, "cgroup.procs") == 0)
      break;
  }
}

void print_cgroup_status(const cfg_t *cfg) {
  const bool limits_set = cfg->conf.memory_limit || cfg->conf.cpu_quota || cfg->conf.pids_limit;

  if (cfg->conf.force_cgroupv1) {
    log_warn("正在使用传统的 Cgroup V1 架构 (由于启用了 --force-cgroupv1)");
    if (limits_set) {
      log_warn("资源限制 (--memory/--cpus/--pids-limit) 需要 Cgroup V2 的支持，"
               "在当前模式下将不会生效。");
    }
    return;
  }

  const bool host_supports_v2 = cgroup_kernel_supports_v2();

  if (!host_supports_v2) {
    log_warn("宿主机内核不支持 Cgroup V2 (自动回退至 V1 架构)");
    if (limits_set) {
      log_warn(
          "[CGROUP] 资源限制 (--memory/--cpus/--pids-limit) 需要 Cgroup V2 的支持，"
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
  char buf[256];
  char path[PATH_MAX + 64];
  snprintf(path, sizeof(path), "%s/cgroup.controllers", cg_path);
  if (read_file(path, buf, sizeof(buf)) <= 0)
    return false;
  return ctrl_in_list(buf, name);
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

  char safe_name[256];
  sanitize_container_name(cfg->conf.container_name, safe_name, sizeof(safe_name));

  char cg[PATH_MAX - 64];
  char path[PATH_MAX + 64], val[64];
  int err = 0;

  snprintf(cg, sizeof(cg), "/sys/fs/cgroup/" PROJECT_NAME "/%s", safe_name);
  if (access(cg, F_OK) != 0) {
    log_warn("[CGROUP] 未找到容器的专属子组，跳过资源限制应用。");
    return -1;
  }

  if (cfg->conf.memory_limit) {
    if (ctrl_supported_v2(cg, "memory")) {
      snprintf(path, sizeof(path), "%s/memory.max", cg);
      snprintf(val, sizeof(val), "%lld", cfg->conf.memory_limit);
      if (write_file(path, val) < 0) {
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
      snprintf(path, sizeof(path), "%s/cpu.max", cg);
      snprintf(val, sizeof(val), "%lld %lld", cfg->conf.cpu_quota, period);
      if (write_file(path, val) < 0) {
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
      snprintf(path, sizeof(path), "%s/pids.max", cg);
      snprintf(val, sizeof(val), "%lld", cfg->conf.pids_limit);
      if (write_file(path, val) < 0) {
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

  char safe_name[256];
  sanitize_container_name(container_name, safe_name, sizeof(safe_name));

  const bool v2 = cgroup_host_is_v2();
  char cg[PATH_MAX - 64];
  char path[PATH_MAX + 64], buf[256];

  if (v2) {
    snprintf(cg, sizeof(cg), "/sys/fs/cgroup/" PROJECT_NAME "/%s", safe_name);
    if (access(cg, F_OK) != 0)
      return -1;
    if (mem) {
      snprintf(path, sizeof(path), "%s/memory.current", cg);
      if (read_file(path, buf, sizeof(buf)) > 0)
        *mem = parse_cgroup_ll(buf);
    }
    if (cpu_us) {
      snprintf(path, sizeof(path), "%s/cpu.stat", cg);
      if (read_file(path, buf, sizeof(buf)) > 0) {
        const char *p = strstr(buf, "usage_usec ");
        if (p)
          *cpu_us = parse_cgroup_ll(p + 11);
      }
    }
    if (pids) {
      snprintf(path, sizeof(path), "%s/pids.current", cg);
      if (read_file(path, buf, sizeof(buf)) > 0)
        *pids = parse_cgroup_ll(buf);
    }
  }
  return 0;
}