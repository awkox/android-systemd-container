#include "asc.h"

std::optional<std::vector<pid_t>> collect_pids() {
    std::vector<pid_t> pids;
    std::error_code ec;

    // 当宿主机使用 Cgroup V2 时，直接遍历 cgroup.procs 收集进程 PID，
    // 大幅减少对庞大 /proc 目录的低效全量扫描。
    if (cgroup_host_is_v2()) {
        fs::path cg_base = fs::path("/sys/fs/cgroup/asc");
        if (fs::exists(cg_base, ec)) {
            auto it = fs::recursive_directory_iterator(cg_base, fs::directory_options::skip_permission_denied, ec);
            auto end = fs::recursive_directory_iterator();
            while (it != end && !ec) {
                if (it->is_regular_file(ec) && it->path().filename() == "cgroup.procs") {
                    if (auto content = read_file_cpp(it->path())) {
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
                it.increment(ec);
            }
            if (!ec) {
                return pids;
            }
            pids.clear();
            ec.clear();
        } else {
            return pids; // 如果目录不存在，说明目前没有任何运行在 Cgroup v2 下的容器
        }
    }
    
    // 退路与 Cgroup V1 模式：使用 C++17 filesystem 遍历 /proc 目录
    for (const auto& entry : fs::directory_iterator("/proc", ec)) {
        if (!entry.is_directory(ec)) continue;
        
        std::string filename = entry.path().filename().string();
        try {
            size_t pos;
            long val = std::stol(filename, &pos);
            // 确保整个字符串都是数字且 > 0
            if (pos == filename.length() && val > 0) {
                pids.push_back(static_cast<pid_t>(val));
            }
        } catch (...) {
            // 忽略非数字目录（如 /proc/sys）
        }
    }
    
    if (ec) return std::nullopt; // 遍历失败
    return pids;
}

bool is_container_init(const pid_t pid) {
  fs::path path = fs::path("proc") / std::to_string(pid) / "status";
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

  fs::path ns_path = fs::path("/proc") / std::to_string(pid) / "ns/pid";
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

  fs::path stat_path = fs::path("/proc") / std::to_string(pid) / "stat";
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

pid_t find_container_init_pid(const char *uuid) {
  if (!uuid || uuid[0] == '\0')
    return 0;

  auto pids_opt = collect_pids();

  if (!pids_opt) return 0;

  for (pid_t pid : *pids_opt) {
    fs::path path = fs::path("/proc") / std::to_string(pid) / "root" / "run/asc" / uuid;

    if (fs::exists(path)) {
      if (is_valid_container_pid(pid)) {
        return pid;
      }
    }
  }

  return 0;
}