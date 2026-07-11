#include "asc.h"

struct virt_snapshot {
  // cgroup 数据
  long long mem_current;    // memory.current
  long long mem_anon;       // memory.stat 中的 anon
  long long mem_file;       // memory.stat 中的 file
  long long mem_slab;       // memory.stat 中的 slab
  double    cpu_busy_sec;   // cpu.stat 中的 usage_usec / 1e6
  bool      valid;          // 数据是否有效
};

static long long read_cg_ll(const char *container_name, const char *file) {
  fs::path path = project_cgroup_dir / container_name / file;
  if (auto content = read_file_cpp(path)) {
    if (content->starts_with("max")) return -1;
    try {
      return std::stoll(*content);
    } catch (...) {
      return -1;
    }
  }
  return -1;
}

static virt_snapshot read_cgroup_snapshot(const char *container_name) {
  virt_snapshot snap = {};
  snap.valid = false;

  // 一次读取 memory.current
  snap.mem_current = read_cg_ll(container_name, "memory.current");

  // 一次读取 memory.stat，解析多个字段
  {
    fs::path path = project_cgroup_dir / container_name / "memory.stat";
    if (auto content = read_file_cpp(path)) {
      std::istringstream iss(*content);
      std::string key;
      long long val;
      while (iss >> key >> val) {
        if (key == "anon")       snap.mem_anon = val;
        else if (key == "file")  snap.mem_file = val;
        else if (key == "slab")  snap.mem_slab = val;
      }
    }
  }

  // 一次读取 cpu.stat
  {
    fs::path path = project_cgroup_dir / container_name / "cpu.stat";
    if (auto content = read_file_cpp(path)) {
      std::istringstream iss(*content);
      std::string key;
      long long val;
      while (iss >> key >> val) {
        if (key == "usage_usec") {
          snap.cpu_busy_sec = static_cast<double>(val) / 1e6;
          break;
        }
      }
    }
  }

  snap.valid = true;
  return snap;
}

/* 就地覆盖写：保留原绑定的挂载 inode（不能用 rename，那会破坏覆盖关系）。
 * 通过 safe_openat_proc() 打开文件，防止各个目录层级的符号链接陷阱。 */
static int write_inplace(const pid_t pid, const fs::path& subpath, std::string_view content) {
  auto_close const int fd = safe_openat_proc(pid, subpath, O_WRONLY, 0);
  if (fd < 0)
    return -1;

  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
    return -1;

  struct statfs sfs;
  if (fstatfs(fd, &sfs) < 0 || sfs.f_type != TMPFS_MAGIC)
    return -1;

  const ssize_t w = write_all(fd, content.data(), content.size());
  if (w == static_cast<ssize_t>(content.size())) {
    if (ftruncate(fd, static_cast<off_t>(content.size())) < 0) {
    }
  }
  return w == static_cast<ssize_t>(content.size()) ? 0 : -1;
}

static int container_cpus(const long long cpu_quota, const long long cpu_period) {
  int host = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  if (host < 1)
    host = 1;
  if (cpu_quota <= 0 || cpu_period <= 0)
    return host;
  int n = static_cast<int>((cpu_quota + cpu_period - 1) / cpu_period);
  return std::clamp(n, 1, host);
}

// 签名改为接收快照引用
static std::optional<std::string> gen_meminfo(const cfg_t *cfg,
                                              const virt_snapshot &snap) {
  const long long mem_limit = cfg->conf.memory_limit;
  const long long mem_used = std::max(0LL, snap.mem_current);  // ← 直接用快照

  std::ifstream f("/proc/meminfo");
  if (!f) return std::nullopt;

  std::vector<std::string> lines;
  std::string line;
  long long host_total_kb = 0;
  
  while (std::getline(f, line)) {
    lines.push_back(line);
    if (line.starts_with("MemTotal:")) {
      std::istringstream iss(line);
      std::string key;
      iss >> key >> host_total_kb;
    }
  }

  double ratio = 1.0;
  if (mem_limit > 0 && host_total_kb > 0)
    ratio = static_cast<double>(mem_limit) / (static_cast<double>(host_total_kb) * 1024.0);

  // 不再单独读 memory.stat，直接用快照
  const long long cg_anon = snap.mem_anon;
  const long long cg_file = snap.mem_file;
  const long long cg_slab = snap.mem_slab;

  std::string result;
  for (const auto& l : lines) {
    std::istringstream iss(l);
    std::string key;
    long long val;
    
    // 如果存在资源限制，按比例和 Cgroup 数据动态修正 meminfo
    if (mem_limit > 0 && (iss >> key >> val) && key.ends_with(':')) {
      key.pop_back(); // 移除键名后的冒号
      std::string unit = l.find(" kB") != std::string::npos ? " kB" : "";
      
      const long long lim_kb = mem_limit / 1024;

      if (key == "MemTotal") val = lim_kb;
      else if (key == "MemFree") val = std::max(0LL, (mem_limit - mem_used) / 1024);
      else if (key == "MemAvailable") val = std::max(0LL, lim_kb - mem_used / 1024);
      else if (key == "SwapTotal" || key == "SwapFree") val = 0;
      else if (key == "AnonPages" && cg_anon >= 0) val = cg_anon / 1024;
      else if ((key == "Cached" || key == "Mapped") && cg_file >= 0) val = cg_file / 1024;
      else if (key == "Slab" && cg_slab >= 0) val = cg_slab / 1024;
      else val = static_cast<long long>(val * ratio);

      if (!unit.empty() && val > lim_kb)
        val = lim_kb;

      result += std::format("{:<16}{:11}{}\n", key + ":", val, unit);
      continue;
    }
    result += l + "\n";
  }
  return result;
}

static std::optional<std::string> gen_cpuinfo(const cfg_t *cfg,
                                              const virt_snapshot &/*snap*/) {
  const int max_cpus = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
  std::ifstream f("/proc/cpuinfo");
  if (!f) return std::nullopt;

  std::string result;
  std::string line;
  while (std::getline(f, line)) {
    if (line.starts_with("processor")) {
      std::istringstream iss(line);
      std::string dummy, colon;
      int id;
      if (iss >> dummy >> colon >> id && colon == ":") {
        if (id >= max_cpus) break; // 超出限额的核心截断输出
      }
    }
    result += line + "\n";
  }
  return result;
}

static std::optional<std::string> gen_stat(const cfg_t *cfg,
                                           const virt_snapshot &/*snap*/) {
  const int max_cpus = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
  std::ifstream f("/proc/stat");
  if (!f) return std::nullopt;

  std::vector<std::string> lines;
  std::string line;
  while (std::getline(f, line)) {
      lines.push_back(line);
  }

  unsigned long long su = 0, sn = 0, ss = 0, si = 0, sio = 0, sir = 0,
                     ssoft = 0, sst = 0, sgu = 0, sgn = 0;
                     
  // 第一轮：聚合被允许的核心时间累加
  for (const auto& l : lines) {
    if (l.starts_with("cpu")) {
      std::istringstream iss(l);
      std::string cpu_label;
      iss >> cpu_label;
      if (cpu_label.size() > 3) {
        try {
          int id = std::stoi(cpu_label.substr(3));
          if (id < max_cpus) {
            unsigned long long u = 0, n = 0, s = 0, i = 0, io = 0, ir = 0, sf = 0, st = 0, gu = 0, gn = 0;
            if (iss >> u >> n >> s >> i >> io >> ir >> sf >> st >> gu >> gn) {
                su += u; sn += n; ss += s; si += i; sio += io; sir += ir;
                ssoft += sf; sst += st; sgu += gu; sgn += gn;
            }
          }
        } catch (...) {}
      }
    }
  }

  std::string result;
  bool agg_done = false;
  
  // 第二轮：修补与截断写入
  for (const auto& l : lines) {
    if (l.starts_with("cpu")) {
      size_t space_idx = l.find(' ');
      std::string cpu_label = space_idx != std::string::npos ? l.substr(0, space_idx) : l;
      
      // 修补全局聚合时间 "cpu  "
      if (cpu_label == "cpu") {
        if (!agg_done) {
          result += std::format("cpu  {} {} {} {} {} {} {} {} {} {}\n",
                                su, sn, ss, si, sio, sir, ssoft, sst, sgu, sgn);
          agg_done = true;
        }
        continue;
      } else if (cpu_label.size() > 3) {
        try {
          int id = std::stoi(cpu_label.substr(3));
          if (id >= max_cpus) continue; // 屏蔽超出的核心
        } catch (...) {}
      }
    }
    result += l + "\n";
  }
  return result;
}

static double container_start_time_secs(const pid_t pid) {
  auto content = read_file_cpp(proc_dir / std::to_string(pid) / "stat");
  if (!content) return -1.0;

  size_t rp = content->rfind(')');
  if (rp != std::string::npos) {
    std::istringstream iss(content->substr(rp + 1));
    std::string state;
    int ppid, pgrp, session, tty_nr, tpgid;
    unsigned int flags;
    unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, num_threads, itrealvalue;
    unsigned long long starttime = 0;
    
    // 直接按顺序提取第 22 个数据单元，防止了旧有的 sscanf('%*d' 大法) 被空格截断或误匹配的风险
    if (iss >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid 
            >> flags >> minflt >> cminflt >> majflt >> cmajflt 
            >> utime >> stime >> cutime >> cstime >> priority 
            >> nice >> num_threads >> itrealvalue >> starttime) {
      if (starttime > 0) {
        const long ticks = sysconf(_SC_CLK_TCK);
        if (ticks > 0) return static_cast<double>(starttime) / static_cast<double>(ticks);
      }
    }
  }
  return -1.0;
}

static std::optional<std::string> gen_uptime(const cfg_t *cfg,
                                             const virt_snapshot &snap) {
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

  const int ccpus = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
  const double busy = snap.cpu_busy_sec;  // ← 直接用快照，不再读文件
  double idle = busy >= 0.0 ? up * ccpus - busy : up * ccpus * 0.1;

  return std::format("{:.2f} {:.2f}\n", up, idle);
}

static std::optional<std::string> gen_loadavg(const cfg_t *cfg,
                                              const virt_snapshot &/*snap*/) {
  auto content = read_file_cpp("/proc/loadavg");
  if (!content) return std::nullopt;

  double l1, l5, l15;
  std::string procs;
  if (!(std::istringstream(*content) >> l1 >> l5 >> l15 >> procs))
    return std::nullopt;

  int run = 0, tot = 0;
  size_t slash = procs.find('/');
  if (slash != std::string::npos) {
    try {
      run = std::stoi(procs.substr(0, slash));
      tot = std::stoi(procs.substr(slash + 1));
    } catch (...) {}
  }

  const int hcpus = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  const int ccpus = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
  const double r = static_cast<double>(ccpus) / static_cast<double>(hcpus);

  int srun = std::max(1, static_cast<int>(run * r));
  int stot = std::max(1, static_cast<int>(tot * r));

  return std::format("{:.2f} {:.2f} {:.2f} {}/{} 0\n", l1 * r, l5 * r, l15 * r, srun, stot);
}

static std::optional<std::string> gen_cpu_sysfs(const cfg_t *cfg) {
  const int n = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
  if (n <= 1) return "0\n";
  return std::format("0-{}\n", n - 1);
}

unsigned long get_pid_ns_inode(const pid_t pid) {
  struct stat st;
  fs::path path = proc_dir / std::to_string(pid) / "ns/pid";
  return stat(path.c_str(), &st) == 0 ? st.st_ino : 0UL;
}

static void bind_vfile(const fs::path& vpath, const fs::path& target, const std::string& content) {
  if (write_file(vpath, content.c_str()) < 0)
    return;
  
  if (!fs::exists(target)) {
    std::ofstream{target}; 
  }
  
  if (bind_mount(vpath, target) < 0)
    log_warn("[VIRT] bind_mount %s -> %s 失败 (将继续执行)", vpath.c_str(), target.c_str());
}

static void virtualize_affinity(const long long cpu_quota, const long long cpu_period) {
  const int n = container_cpus(cpu_quota, cpu_period);
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
    virtualize_affinity(cfg->conf.cpu_quota, cfg->conf.cpu_period);

  if (!create_directories_with_permission(vproc_dir)) {
    log_warn("[VIRT] 创建 /run/asc/vproc 失败: %s", strerror(errno));
    return -1;
  }
  if (domount("none", vproc_dir.string(), "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=755,size=1M") < 0) {
    log_warn("[VIRT] tmpfs 挂载失败: %s", strerror(errno));
    return -1;
  }

  const virt_snapshot snap = read_cgroup_snapshot(cfg->rt.container_name);

  using GenFunc = std::optional<std::string>(*)(const cfg_t*, const virt_snapshot&);
  const struct {
    const char *name;
    GenFunc gen;
    bool enabled;
  } proc_files[] = {
    {"meminfo", gen_meminfo, has_mem},
    {"cpuinfo", gen_cpuinfo, has_cpu},
    {"stat",    gen_stat,    has_cpu},
    {"uptime",  gen_uptime,  true},
    {"loadavg", gen_loadavg, true},
  };

  for (const auto &pf : proc_files) {
    if (!pf.enabled) continue;
    auto opt_str = pf.gen(cfg, snap);
    if (!opt_str)
      continue;

    fs::path vpath = vproc_dir / pf.name;
    fs::path target = proc_dir / pf.name;
    bind_vfile(vpath, target, *opt_str);
  }

  if (has_cpu) {
    fs::path cpu_sysfs_path = vproc_dir / "cpu_sysfs";
    if (create_directories_with_permission(cpu_sysfs_path)) {
      const int n = container_cpus(cfg->conf.cpu_quota, cfg->conf.cpu_period);
      for (int i = 0; i < n; i++) {
        fs::path vcpu = cpu_sysfs_path / std::format("cpu{}", i);
        fs::path realcpu = fs::path("/sys/devices/system/cpu") / std::format("cpu{}", i);
        
        if (fs::exists(realcpu)) {
          std::error_code ec;
          if (fs::create_directory(vcpu, ec)) {
            if (bind_mount(realcpu, vcpu) < 0)
              log_warn("[VIRT] bind_mount %s -> %s 失败", realcpu.c_str(), vcpu.c_str());
          }
        }
      }

      const std::array<const char*, 3> sysfs_names = {"online", "possible", "present"};
      for (const char* name : sysfs_names) {
        auto opt_str = gen_cpu_sysfs(cfg);
        if (!opt_str)
          continue;
        fs::path vpath = cpu_sysfs_path / name;
        write_file(vpath, opt_str->c_str());
      }

      if (bind_mount(cpu_sysfs_path, "/sys/devices/system/cpu") < 0)
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

  // === 每周期只读一次 cgroup ===
  const virt_snapshot snap = read_cgroup_snapshot(cfg->rt.container_name);

  fs::path container_vproc_dir = proc_dir / std::to_string(cfg->rt.container_pid) / "root" / vproc_dir;

  const bool has_mem = cfg->conf.memory_limit > 0;
  const bool has_cpu = cfg->conf.cpu_quota > 0;

  using GenFunc = std::optional<std::string>(*)(const cfg_t*, const virt_snapshot&);
  const struct {
    const char *name;
    GenFunc gen;
    bool enabled;
  } dyn[] = {
    {"meminfo", gen_meminfo, has_mem},
    {"stat",    gen_stat,    has_cpu},
    {"uptime",  gen_uptime,  true},
    {"loadavg", gen_loadavg, true},
  };

  for (const auto &d : dyn) {
    if (!d.enabled) continue;

    auto opt_str = d.gen(cfg, snap);  // ← 传入快照
    if (!opt_str) {
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 生成器 gen_%s 返回了 nullopt", d.name);
      continue;
    }

    fs::path path = container_vproc_dir / d.name;
    fs::path subpath = vproc_dir / d.name;

    if (write_inplace(cfg->rt.container_pid, subpath, *opt_str) < 0)
      write_monitor_debug_log(cfg->rt.container_name,
                              "[VIRT] 就地覆盖写入 write_inplace 失败: %s (%s)", path.c_str(),
                              strerror(errno));
  }
}