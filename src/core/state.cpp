#include "asc.h"

bool is_container_running(char *uuid, pid_t *pid_out) {
  if (!uuid || uuid[0] == '\0')
    return false;

  const pid_t deep_pid = find_container_init_pid(uuid);
  if (deep_pid > 0) {
    if (pid_out)
      *pid_out = deep_pid;
    return true;
  }

  return false;
}

std::vector<std::string> collect_active_uuids(size_t max_uuids) {
  std::vector<std::string> uuids;
  auto pids_opt = collect_pids();
  if (!pids_opt) return uuids;

  std::error_code ec;
  for (pid_t pid : *pids_opt) {
    if (uuids.size() >= max_uuids) break;

    // 优雅拼接路径
    fs::path marker_dir = std::format("/proc/{}/root{}", pid, FORK_MARKER);
    if (!fs::exists(marker_dir, ec)) continue;

    for (const auto& entry : fs::directory_iterator(marker_dir, ec)) {
      if (uuids.size() >= max_uuids) break;

      std::string name = entry.path().filename().string();
      // 使用 C++ 标准库算法优雅验证纯十六进制 32 位 UUID
      if (name.length() == UUID_LEN && 
          std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isxdigit(c); })) {
        uuids.push_back(name);
      }
    }
  }
  return uuids;
}
