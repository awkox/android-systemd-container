#include "asc.h"

// 优化 1: 将 collect_pids 降级为单层迭代，避免扫描无关的控制文件
std::optional<std::vector<pid_t>> collect_pids() {
    std::vector<pid_t> pids;
    std::error_code ec;

    if (!fs::exists(project_cgroup_dir, ec)) {
        return pids;
    }

    for (const auto& entry : fs::directory_iterator(project_cgroup_dir, ec)) {
        if (entry.is_directory(ec)) {
            fs::path procs_file = entry.path() / "cgroup.procs";
            if (auto content = read_file_cpp(procs_file)) {
                size_t pos = 0;
                while (pos < content->length()) {
                    size_t end_pos = content->find('\n', pos);
                    if (end_pos == std::string::npos) end_pos = content->length();
                    if (end_pos > pos) {
                        try {
                            long val = std::stol(content->substr(pos, end_pos - pos));
                            if (val > 0) pids.push_back(static_cast<pid_t>(val));
                        } catch (...) {}
                    }
                    pos = end_pos + 1;
                }
            }
        }
    }
    if (ec) return std::nullopt;
    return pids;
}

bool is_container_init(const pid_t pid) {
  fs::path path = proc_dir / std::to_string(pid) / "status";
  auto_fclose FILE *f = fopen(path.c_str(), "re");
  if (!f)
    return false;

  char line[1024];
  bool is_init = false;
  bool nspid_found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "NSpid:", 6) == 0) {
      nspid_found = true;
      char *p = line + 6;
      const char *last_val = nullptr;
      char *saveptr;
      const char *token = strtok_r(p, " \t\n\r", &saveptr);
      while (token) {
        last_val = token;
        token = strtok_r(nullptr, " \t\n\r", &saveptr);
      }
      if (last_val && strcmp(last_val, "1") == 0) {
        is_init = true;
      }
      break;
    }
  }

  if (nspid_found)
    return is_init;

  struct stat st_pid, st_host;

  fs::path ns_path = proc_dir / std::to_string(pid) / "ns/pid";
  if (stat(ns_path.c_str(), &st_pid) < 0)
    return false;

  if (stat("/proc/1/ns/pid", &st_host) < 0)
    return false;

  return st_pid.st_ino != st_host.st_ino;
}

long get_container_uptime(const pid_t pid) {
  if (pid <= 0)
    return -1;

  long clk_tck = sysconf(_SC_CLK_TCK);
  if (clk_tck <= 0)
    clk_tck = 100;

  fs::path stat_path = proc_dir / std::to_string(pid) / "stat";
  unsigned long long start_ticks = 0;
  {
    if (auto content = read_file_cpp(stat_path)) {
      const char *p = strrchr(content->c_str(), ')');
      if (p) {
        sscanf(p + 1, " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &start_ticks);
      }
    }
  }
  if (start_ticks == 0)
    return -1;

  {
    auto_fclose FILE *f = fopen("/proc/uptime", "r");
    if (!f)
      return -1;
    double host_uptime_sec = 0.0;
    if (fscanf(f, "%lf", &host_uptime_sec) != 1)
      host_uptime_sec = 0.0;
    const long uptime_sec = static_cast<long>(host_uptime_sec - static_cast<double>(start_ticks) / static_cast<double>(clk_tck));
    return uptime_sec < 0 ? 0 : uptime_sec;
  }
}

// 优化 2: O(1) 精确制导查找目标 PID
pid_t find_container_init_pid(const char *container_name, const char *uuid) {
  if (!uuid || uuid[0] == '\0')
    return 0;

  if (container_name && container_name[0]) {
    fs::path cg_procs = project_cgroup_dir / container_name / "cgroup.procs";
    if (auto content = read_file_cpp(cg_procs)) {
      size_t pos = 0;
      while (pos < content->length()) {
        size_t end_pos = content->find('\n', pos);
        if (end_pos == std::string::npos) end_pos = content->length();
        if (end_pos > pos) {
          try {
            long val = std::stol(content->substr(pos, end_pos - pos));
            if (val > 0) {
              pid_t pid = static_cast<pid_t>(val);
              fs::path path = proc_dir / std::to_string(pid) / "root/run/asc" / uuid;
              
              // 验证进程身份
              if (fs::exists(path) && is_valid_container_pid(pid)) {
                return pid;
              }
            }
          } catch (...) {}
        }
        pos = end_pos + 1;
      }
    }
    // 兜底设计：如果在 V2 cgroup 没找到目标，不直接 return 0，
    // 因为可能存在用户使用 force_cgroupv1=true 的异常覆写情况。转入下方全局扫描。
  }

  // 慢速通道 (Slow Path): Cgroup V1 或是缺乏容器名，回退到全局扫描
  auto pids_opt = collect_pids();
  if (!pids_opt) return 0;

  for (pid_t pid : *pids_opt) {
    fs::path path = proc_dir / std::to_string(pid) / "root/run/asc" / uuid;
    if (fs::exists(path)) {
      if (is_valid_container_pid(pid)) {
        return pid;
      }
    }
  }

  return 0;
}