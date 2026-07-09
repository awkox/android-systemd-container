#include "asc.h"

/* 就地覆盖写：保留原绑定的挂载 inode（不能用 rename，那会破坏覆盖关系）。
 * 通过 safe_openat_proc() 打开文件，防止各个目录层级的符号链接陷阱。 */
static int write_inplace(const pid_t pid, const char *subpath, const char *buf,
                         const size_t len) {
  auto_close const int fd = safe_openat_proc(pid, subpath, O_WRONLY, 0);
  if (fd < 0)
    return -1;

  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
    return -1;

  struct statfs sfs;
  if (fstatfs(fd, &sfs) < 0 || sfs.f_type != TMPFS_MAGIC)
    return -1;

  const ssize_t w = write_all(fd, buf, len);
  if (w == static_cast<ssize_t>(len)) {
    if (ftruncate(fd, static_cast<off_t>(len)) < 0) {
    }
  }
  return w == static_cast<ssize_t>(len) ? 0 : -1;
}

static int container_cpus(const asc_conf_t *conf) {
  int host = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  if (host < 1)
    host = 1;
  if (conf->cpu_quota <= 0 || conf->cpu_period <= 0)
    return host;
  int n = static_cast<int>((conf->cpu_quota + conf->cpu_period - 1) / conf->cpu_period);
  if (n < 1)
    n = 1;
  if (n > host)
    n = host;
  return n;
}

static long long read_cg_ll(const char *container_name, const char *file) {
  fs::path path = fs::path("/sys/fs/cgroup/asc") / container_name / file;
  auto content = read_file_cpp(path);
  if (!content)
    return -1;
  if (strncmp(content->c_str(), "max", 3) == 0)
    return -1; 
  char *end;
  const long long v = strtoll(content->c_str(), &end, 10);
  return end == content->c_str() ? -1 : v;
}

static char *gen_meminfo(const cfg_t *cfg, size_t *out_len) {
  const long long mem_limit = cfg->conf.memory_limit; 
  long long mem_used = read_cg_ll(cfg->rt.container_name, "memory.current");
  if (mem_used < 0)
    mem_used = 0;

  auto_fclose FILE *f = fopen("/proc/meminfo", "r");
  if (!f)
    return nullptr;

  long long host_total_kb = 0;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "MemTotal: %lld", &host_total_kb) == 1)
      break;
  }
  rewind(f);

  double ratio = 1.0;
  if (mem_limit > 0 && host_total_kb > 0)
    ratio = static_cast<double>(mem_limit) / (static_cast<double>(host_total_kb) * 1024.0);

  long long cg_anon = -1, cg_file = -1, cg_slab = -1;
  {
    fs::path path = fs::path("/sys/fs/cgroup/asc") / cfg->rt.container_name / fs::path("memory.stat");
    if (auto content = read_file_cpp(path)) {
      const char *p;
      if ((p = strstr(content->c_str(), "anon ")))
        sscanf(p + 5, "%lld", &cg_anon);
      if ((p = strstr(content->c_str(), "file ")))
        sscanf(p + 5, "%lld", &cg_file);
      if ((p = strstr(content->c_str(), "slab ")))
        sscanf(p + 5, "%lld", &cg_slab);
    }
  }

  size_t cap = 16384;
  char *buf = static_cast<char *>(malloc(cap));
  if (!buf)
    return nullptr;
  size_t off = 0;

  while (fgets(line, sizeof(line), f)) {
    if (off + 512 >= cap) {
      cap *= 2;
      char *nb = static_cast<char *>(realloc(buf, cap));
      if (!nb) {
        free(buf);
        return nullptr;
      }
      buf = nb;
    }

    char key[128];
    long long val;
    const int has_kb = strstr(line, " kB") != nullptr;

    if (sscanf(line, "%127[^:]: %lld", key, &val) == 2 && mem_limit > 0) {
      const long long lim_kb = mem_limit / 1024;

      if (!strcmp(key, "MemTotal"))
        val = lim_kb;
      else if (!strcmp(key, "MemFree"))
        val = (mem_limit - mem_used) / 1024 > 0 ? (mem_limit - mem_used) / 1024
                                                : 0;
      else if (!strcmp(key, "MemAvailable")) {
        val = lim_kb - mem_used / 1024;
        if (val < 0)
          val = 0;
      } else if (!strcmp(key, "SwapTotal") || !strcmp(key, "SwapFree"))
        val = 0;
      else if (!strcmp(key, "AnonPages") && cg_anon >= 0)
        val = cg_anon / 1024;
      else if ((!strcmp(key, "Cached") || !strcmp(key, "Mapped")) &&
               cg_file >= 0)
        val = cg_file / 1024;
      else if (!strcmp(key, "Slab") && cg_slab >= 0)
        val = cg_slab / 1024;
      else
        val = static_cast<long long>(val * ratio);

      if (has_kb && val > lim_kb)
        val = lim_kb;

      char fkey[130];
      snprintf(fkey, sizeof(fkey), "%s:", key);
      const int n = snprintf(buf + off, cap - off, "%-16s%11lld kB\n", fkey, val);
      if (n > 0)
        off += static_cast<size_t>(n);
      continue;
    }

    const size_t len = strlen(line);
    if (off + len < cap) {
      memcpy(buf + off, line, len);
      off += len;
    }
  }
  buf[off] = '\0';
  *out_len = off;
  return buf;
}

static char *gen_cpuinfo(const cfg_t *cfg, size_t *out_len) {
  const int max_cpus = container_cpus(&cfg->conf);
  auto_fclose FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return nullptr;

  size_t cap = 65536;
  char *buf = static_cast<char *>(malloc(cap));
  if (!buf)
    return nullptr;
  size_t off = 0;
  int cur_cpu = -1;
  char line[4096];

  while (fgets(line, sizeof(line), f)) {
    int id;
    if (sscanf(line, "processor : %d", &id) == 1)
      cur_cpu = id;
    if (cur_cpu >= max_cpus)
      break;
    const size_t len = strlen(line);
    if (off + len + 1 >= cap) {
      cap *= 2;
      char *nb = static_cast<char *>(realloc(buf, cap));
      if (!nb) {
        free(buf);
        return nullptr;
      }
      buf = nb;
    }
    memcpy(buf + off, line, len);
    off += len;
  }
  buf[off] = '\0';
  *out_len = off;
  return buf;
}

static char *gen_stat(const cfg_t *cfg, size_t *out_len) {
  const int max_cpus = container_cpus(&cfg->conf);
  auto_fclose FILE *f = fopen("/proc/stat", "r");
  if (!f)
    return nullptr;

  size_t cap = 65536;
  char *buf = static_cast<char *>(malloc(cap));
  if (!buf)
    return nullptr;
  size_t off = 0;
  char line[2048];

  unsigned long long su = 0, sn = 0, ss = 0, si = 0, sio = 0, sir = 0,
                     ssoft = 0, sst = 0, sgu = 0, sgn = 0;
  while (fgets(line, sizeof(line), f)) {
    int id;
    if (sscanf(line, "cpu%d", &id) == 1 && id < max_cpus) {
      unsigned long long u = 0, n = 0, s = 0, i = 0, io = 0, ir = 0, 
                         sf = 0, st = 0, gu = 0, gn = 0;
      sscanf(line, "cpu%*d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
             &u, &n, &s, &i, &io, &ir, &sf, &st, &gu, &gn);
      su += u; sn += n; ss += s; si += i; sio += io; sir += ir;
      ssoft += sf; sst += st; sgu += gu; sgn += gn;
    }
  }
  rewind(f);

  bool agg_done = false;
  while (fgets(line, sizeof(line), f)) {
    if (off + sizeof(line) >= cap) {
      cap *= 2;
      char *nb = static_cast<char *>(realloc(buf, cap));
      if (!nb) {
        free(buf);
        return nullptr;
      }
      buf = nb;
    }
    if (strncmp(line, "cpu ", 4) == 0) {
      if (!agg_done) {
        const int n =
            snprintf(buf + off, cap - off,
                     "cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
                     su, sn, ss, si, sio, sir, ssoft, sst, sgu, sgn);
        if (n > 0)
          off += static_cast<size_t>(n);
        agg_done = true;
      }
      continue;
    }
    int id;
    if (sscanf(line, "cpu%d", &id) == 1 && id >= max_cpus)
      continue;
    const size_t len = strlen(line);
    memcpy(buf + off, line, len);
    off += len;
  }
  buf[off] = '\0';
  *out_len = off;
  return buf;
}

static double cg_cpu_busy_secs(const char *container_name) {
  fs::path path = fs::path("/sys/fs/cgroup/asc") / container_name / fs::path("cpu.stat");
  auto content = read_file_cpp(path);
  if (!content)
    return -1.0;
  const char *p = strstr(content->c_str(), "usage_usec ");
  if (!p)
    return -1.0;
  char *end;
  const long long usec = strtoll(p + 11, &end, 10);
  return end == p + 11 ? -1.0 : static_cast<double>(usec) / 1e6;
}

static double container_start_time_secs(const pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(pid));
  auto_fclose FILE *f = fopen(path, "r");
  if (!f)
    return -1.0;
  unsigned long long starttime = 0;
  char buf[1024];
  if (fgets(buf, sizeof(buf), f)) {
    char *p = strrchr(buf, ')');
    if (p) sscanf(p + 1, " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &starttime);
  }
  if (starttime == 0)
    return -1.0;
  const long ticks = sysconf(_SC_CLK_TCK);
  if (ticks <= 0)
    return -1.0;
  return static_cast<double>(starttime) / static_cast<double>(ticks);
}

static char *gen_uptime(const cfg_t *cfg, size_t *out_len) {
  struct timespec boot;
  clock_gettime(CLOCK_BOOTTIME, &boot);
  const double boottime = static_cast<double>(boot.tv_sec) + static_cast<double>(boot.tv_nsec) / 1e9;

  double up = -1.0;
  if (cfg->rt.container_pid > 0) {
    const double proc_start = container_start_time_secs(cfg->rt.container_pid);
    if (proc_start > 0.0)
      up = boottime - proc_start;
  }
  if (up < 0.0) {
    up = boottime - (static_cast<double>(cfg->rt.start_time.tv_sec) +
                     static_cast<double>(cfg->rt.start_time.tv_nsec) / 1e9);
  }
  if (up < 0.0)
    up = 0.0;

  const int ccpus = container_cpus(&cfg->conf);
  const double busy = cg_cpu_busy_secs(cfg->rt.container_name);
  double idle = busy >= 0.0 ? up * ccpus - busy : up * ccpus * 0.1;
  if (idle < 0.0)
    idle = 0.0;

  char *buf = static_cast<char *>(malloc(64));
  if (!buf)
    return nullptr;
  *out_len = static_cast<size_t>(snprintf(buf, 64, "%.2f %.2f\n", up, idle));
  return buf;
}

static char *gen_loadavg(const cfg_t *cfg, size_t *out_len) {
  auto_fclose FILE *f = fopen("/proc/loadavg", "r");
  if (!f)
    return nullptr;
  double l1, l5, l15;
  int run, tot;
  if (fscanf(f, "%lf %lf %lf %d/%d %*d", &l1, &l5, &l15, &run, &tot) != 5)
    return nullptr;

  const int hcpus = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  const int ccpus = container_cpus(&cfg->conf);
  const double r = static_cast<double>(ccpus) / static_cast<double>(hcpus);

  int srun = static_cast<int>(run * r);
  if (srun < 1 && run > 0)
    srun = 1;
  int stot = static_cast<int>(tot * r);
  if (stot < 1)
    stot = 1;

  char *buf = static_cast<char *>(malloc(1024));
  if (!buf)
    return nullptr;
  *out_len = static_cast<size_t>(snprintf(buf, 1024, "%.2f %.2f %.2f %d/%d 0\n", 
                                          l1 * r, l5 * r, l15 * r, srun, stot));
  return buf;
}

static char *gen_cpu_sysfs(const cfg_t *cfg, size_t *out_len) {
  const int n = container_cpus(&cfg->conf);
  char *buf = static_cast<char *>(malloc(32));
  if (!buf)
    return nullptr;
  *out_len = static_cast<size_t>(n == 1 ? snprintf(buf, 32, "0\n")
                                        : snprintf(buf, 32, "0-%d\n", n - 1));
  return buf;
}

unsigned long get_pid_ns_inode(const pid_t pid) {
  struct stat st;
  fs::path path = fs::path("/proc") / std::to_string(pid) / "ns/pid";
  return stat(path.c_str(), &st) == 0 ? st.st_ino : 0UL;
}

static void bind_vfile(const char *vpath, const char *target,
                       const char *content) {
  if (write_file(vpath, content) < 0)
    return;
  if (!fs::exists(target)) {
    const int fd = open(target, O_WRONLY | O_CREAT | O_CLOEXEC, 0444);
    if (fd >= 0)
      close(fd);
  }
  if (bind_mount(vpath, target) < 0)
    log_warn("[VIRT] bind_mount %s -> %s 失败 (将继续执行)", vpath, target);
}

static void virtualize_affinity(const asc_conf_t *conf) {
  const int n = container_cpus(conf);
  const int host = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  if (n >= host || n <= 0)
    return;

  cpu_set_t mask;
  CPU_ZERO(&mask);
  if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) < 0)
    return;

  int count = 0;
  cpu_set_t new_mask;
  CPU_ZERO(&new_mask);

  for (int i = 0; i < CPU_SETSIZE && count < n; i++) {
    if (CPU_ISSET(i, &mask)) {
      CPU_SET(i, &new_mask);
      count++;
    }
  }

  if (count > 0) {
    if (sched_setaffinity(0, sizeof(cpu_set_t), &new_mask) < 0) {
    }
  }
}

int virtualize_init(const cfg_t *cfg) {
  const bool has_mem = cfg->conf.memory_limit > 0;
  const bool has_cpu = cfg->conf.cpu_quota > 0;

  if (has_cpu)
    virtualize_affinity(&cfg->conf);

  if (!fs::create_directories("/run/asc/vproc")) {
    log_warn("[VIRT] 创建 /run/asc/vproc 失败: %s", strerror(errno));
    return -1;
  }
  if (domount("none", "/run/asc/vproc", "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=755,size=1M") < 0) {
    log_warn("[VIRT] tmpfs 挂载失败: %s", strerror(errno));
    return -1;
  }

  const struct {
    const char *name;
    char *(*gen)(const cfg_t *, size_t *);
    bool enabled;
  } proc_files[] = {
    {"meminfo", gen_meminfo, has_mem},
    {"cpuinfo", gen_cpuinfo, has_cpu},
    {"stat", gen_stat, has_cpu},
    {"uptime", gen_uptime, true},
    {"loadavg", gen_loadavg, true},
  };

  for (size_t i = 0; i < std::size(proc_files); i++) {
    if (!proc_files[i].enabled)
      continue;
    size_t len = 0;
    auto_free char *buf = proc_files[i].gen(cfg, &len);
    if (!buf)
      continue;

    fs::path vpath = fs::path("/run/asc/vproc") / proc_files[i].name;
    fs::path target = fs::path("/proc") / proc_files[i].name;
    bind_vfile(vpath.c_str(), target.c_str(), buf);
  }

  if (has_cpu) {
    if (fs::create_directories("/run/asc/vproc/cpu_sysfs")) {
      const int n = container_cpus(&cfg->conf);
      for (int i = 0; i < n; i++) {
        fs::path vcpu = fs::path("/run/asc/vproc/cpu_sysfs") / ("cpu" + std::to_string(i));
        fs::path realcpu = fs::path("/sys/devices/system/cpu") / ("cpu" + std::to_string(i));
        if (fs::exists(realcpu)) {
          if (mkdir(vcpu.c_str(), 0755) == 0) {
            if (bind_mount(realcpu.c_str(), vcpu.c_str()) < 0)
              log_warn("[VIRT] bind_mount %s -> %s 失败", realcpu.c_str(), vcpu.c_str());
          }
        }
      }

      const char *sysfs_names[] = {"online", "possible", "present"};
      for (size_t i = 0; i < std::size(sysfs_names); i++) {
        size_t len = 0;
        auto_free char *buf = gen_cpu_sysfs(cfg, &len);
        if (!buf)
          continue;
        fs::path vpath = fs::path("/run/asc/vproc/cpu_sysfs") / sysfs_names[i];
        write_file(vpath.c_str(), buf);
      }

      if (bind_mount("/run/asc/vproc/cpu_sysfs", "/sys/devices/system/cpu") < 0)
        log_warn("[VIRT] 屏蔽 /sys/devices/system/cpu 失败 (htop 可能会显示宿主机核心)");
    }
  }

  log_info("[VIRT] 资源虚拟化处于活动状态 (mem=%d cpu=%d uptime=1 loadavg=1)",
           has_mem, has_cpu);
  return 0;
}

void virtualize_update(const cfg_t *cfg) {
  if (cfg->rt.container_pid <= 0)
    return;

  if (cfg->rt.ns_inode) {
    const unsigned long live = get_pid_ns_inode(cfg->rt.container_pid);
    if (live != cfg->rt.ns_inode) {
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 更新跳过: 命名空间 ns_inode 不匹配 "
                              "(预期为 %lu, 得到 %lu) pid=%d",
                              cfg->rt.ns_inode, live, static_cast<int>(cfg->rt.container_pid));
      return;
    }
  }

  fs::path vproc_dir = fs::path("/proc") / std::to_string(cfg->rt.container_pid) / "root" / "run/asc/vproc";
  struct stat st_dir;
  if (stat(vproc_dir.c_str(), &st_dir) != 0 || !S_ISDIR(st_dir.st_mode)) {
    return;
  }

  const bool has_mem = cfg->conf.memory_limit > 0;
  const bool has_cpu = cfg->conf.cpu_quota > 0;

  const struct {
    const char *name;
    char *(*gen)(const cfg_t *, size_t *);
    bool enabled;
  } dyn[] = {
    {"meminfo", gen_meminfo, has_mem},
    {"stat", gen_stat, has_cpu},
    {"uptime", gen_uptime, true},
    {"loadavg", gen_loadavg, true},
  };

  for (size_t i = 0; i < std::size(dyn); i++) {
    if (!dyn[i].enabled)
      continue;
    size_t len = 0;
    auto_free char *buf = dyn[i].gen(cfg, &len);
    if (!buf) {
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 生成器 gen_%s 返回了空指针 NULL", dyn[i].name);
      continue;
    }

    struct stat st;
    fs::path path = fs::path("/proc") / std::to_string(cfg->rt.container_pid) / "root" /
                    "run/asc/vproc" / dyn[i].name;
    if (stat(path.c_str(), &st) != 0) {
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 虚拟文件丢失: %s (%s)", path.c_str(),
                              strerror(errno));
      continue;
    }

    fs::path subpath = fs::path("/run/asc/vproc") / dyn[i].name;

    if (write_inplace(cfg->rt.container_pid, subpath.c_str(), buf, len) < 0)
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 就地覆盖写入 write_inplace 失败: %s (%s)", path.c_str(),
                              strerror(errno));
  }
}