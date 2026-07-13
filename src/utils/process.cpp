#include "asc.h"

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

unsigned long get_pid_ns_inode(const pid_t pid) {
  struct stat st;
  fs::path path = proc_dir / std::to_string(pid) / "ns/pid";
  return stat(path.c_str(), &st) == 0 ? st.st_ino : 0UL;
}

// 优化: O(1) 纯 CgroupV2 目录解析
pid_t find_container_init_pid(std::string_view container_name) {
  fs::path cg_root = project_cgroup_dir / container_name;
  std::error_code ec;
  
  if (!fs::exists(cg_root, ec)) return 0;

  // 遍历 cg_root 及其所有子目录
  for (const auto& entry : fs::recursive_directory_iterator(cg_root, fs::directory_options::skip_permission_denied, ec)) {
    if (entry.path().filename() == "cgroup.procs") {
      if (auto content = read_file_cpp(entry.path())) {
        size_t pos = 0;
        while (pos < content->length()) {
          size_t end_pos = content->find('\n', pos);
          if (end_pos == std::string::npos) end_pos = content->length();
          if (end_pos > pos) {
            try {
              long val = std::stol(content->substr(pos, end_pos - pos));
              if (val > 0) {
                pid_t pid = static_cast<pid_t>(val);
                if (is_valid_container_pid(pid)) {
                  return pid; // 找到了真正的 Init 进程
                }
              }
            } catch (...) {}
          }
          pos = end_pos + 1;
        }
      }
    }
  }

  return 0;
}