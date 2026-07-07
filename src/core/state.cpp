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

int collect_active_uuids(char uuids[][UUID_LEN + 1], const int max_uuids) {
  if (!uuids || max_uuids <= 0)
    return 0;

  auto_free pid_t *pids = nullptr;
  size_t count = 0;
  char path[PATH_MAX];
  int found = 0;

  if (collect_pids(&pids, &count) < 0)
    return 0;

  for (size_t i = 0; i < count && found < max_uuids; i++) {
    if (build_proc_root_path(pids[i], FORK_MARKER, path, sizeof(path)) < 0)
      continue;
    if (access(path, F_OK) != 0)
      continue;

    auto_closedir DIR *d = opendir(path);
    if (!d)
      continue;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr && found < max_uuids) {
      if (strlen(ent->d_name) != UUID_LEN)
        continue;
      /* 验证是否为纯十六进制字符，UUID 标记文件必须是 32 个十六进制字符 */
      bool is_uuid = true;
      for (int j = 0; j < UUID_LEN; j++) {
        const char c = ent->d_name[j];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
          is_uuid = false;
          break;
        }
      }
      if (is_uuid) {
        memcpy(uuids[found], ent->d_name, UUID_LEN);
        uuids[found][UUID_LEN] = '\0';
        found++;
      }
    }
  }

  return found;
}