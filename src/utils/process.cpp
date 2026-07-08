#include "asc.h"

std::optional<std::vector<pid_t>> collect_pids() {
    std::vector<pid_t> pids;
    std::error_code ec;
    
    // 使用 C++17 filesystem 遍历目录，更安全简洁
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (!entry.is_directory()) continue;
        
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

int build_proc_root_path(const pid_t pid, const char *suffix, char *buf,
                         const size_t size) {
  int r;
  if (suffix && suffix[0])
    r = snprintf(buf, size, PROC_ROOT_FMT "%s", pid, suffix);
  else
    r = snprintf(buf, size, PROC_ROOT_FMT, pid);
  return r > 0 && static_cast<size_t>(r) < size ? 0 : -1;
}

bool is_container_init(const pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  auto_fclose FILE *f = fopen(path, "re");
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
  char ns_path[PATH_MAX];

  snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/pid", pid);
  if (stat(ns_path, &st_pid) < 0)
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

  char stat_path[PATH_MAX];
  snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", static_cast<int>(pid));

  unsigned long long start_ticks = 0;
  {
    char buf[1024];
    if (read_file(stat_path, buf, sizeof(buf)) > 0) {
      char *p = strrchr(buf, ')');
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

  char marker[PATH_MAX];
  snprintf(marker, sizeof(marker), FORK_MARKER "/%s", uuid);

  char path[PATH_MAX];

  auto pids_opt = collect_pids();

  if (!pids_opt) return 0;

  for (pid_t pid : *pids_opt) {
    if (build_proc_root_path(pid, FORK_MARKER, path, sizeof(path)) < 0)
      continue;

    if (access(path, F_OK) == 0) {
      build_proc_root_path(pid, marker, path, sizeof(path));
      if (access(path, F_OK) == 0) {
        if (is_valid_container_pid(pid)) {
          return pid;
        }
      }
    }
  }

  return 0;
}