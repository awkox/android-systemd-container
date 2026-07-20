#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "utils/process.h"
#include "utils/path.h"

bool is_container_init(const pid_t pid) {
  std::filesystem::path path = proc_dir / std::to_string(pid) / "status";
  std::ifstream file(path);
  if (!file) return false;

  std::string line;
  bool nspid_found = false;
  bool is_init = false;

  while (std::getline(file, line)) {
    if (line.starts_with("NSpid:")) {
      nspid_found = true;
      std::istringstream iss(line.substr(6));
      std::string current, last_val;
      while (iss >> current) {
        last_val = std::move(current);
      }
      return last_val == "1";
    }
  }

  return false;
}

bool is_valid_container_pid(const pid_t pid) {
  std::filesystem::path path = proc_dir / std::to_string(pid) / "root";
  if (!std::filesystem::exists(path)) return false;
  if (!is_container_init(pid)) return false;
  return true;
}

unsigned long get_pid_ns_inode(const pid_t pid) {
  struct stat st;
  std::filesystem::path path = proc_dir / std::to_string(pid) / "ns/pid";
  return stat(path.c_str(), &st) == 0 ? st.st_ino : 0UL;
}

pid_t find_container_init_pid(std::string_view container_name) {
  std::filesystem::path cg_root = project_cgroup_dir / container_name;
  std::error_code ec;
  if (!std::filesystem::exists(cg_root, ec)) return 0;

  for (const auto &entry : std::filesystem::recursive_directory_iterator(cg_root, std::filesystem::directory_options::skip_permission_denied, ec)) {
    if (entry.path().filename() == "cgroup.procs") {
      std::ifstream file(entry.path());
      pid_t pid;
      while (file >> pid) {
        if (pid > 0 && is_valid_container_pid(pid)) {
          return pid;
        }
      }
    }
  }
  return 0;
}