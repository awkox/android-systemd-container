#include "asc.h"

bool is_container_running(const cfg_t *cfg, pid_t *pid_out) {
  if (cfg->uuid[0] == '\0')
    return false;

  const pid_t deep_pid = find_container_init_pid(cfg->uuid);
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
      /* Verify it's all hex chars -- UUID marker files are 32 hex chars */
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

int show_containers(const cfg_t *cfg) {
  int cap = 32;

  /* 总跟踪数 = config 目录下的文件夹数量 */
  char container_dir[1024];
  snprintf(container_dir, sizeof(container_dir), "%s/%s", get_runtime_dir(),
           RUNTIME_CONFIG_SUBDIR);
  const int totalcount = count_folders(container_dir);

  auto_free struct container_info *containers =
    malloc(cap * sizeof(struct container_info));
  if (!containers)
    return -1;

  /* Scan /proc for running containers */
  auto_free pid_t *pids = nullptr;
  size_t pcount = 0;
  char path[PATH_MAX];

  if (collect_pids(&pids, &pcount) >= 0) {
    int count = 0;
    size_t max_name_len = 4; /* "NAME" */

    for (size_t i = 0; i < pcount; i++) {
      if (build_proc_root_path(pids[i], FORK_MARKER, path, sizeof(path)) < 0)
        continue;
      if (access(path, F_OK) != 0)
        continue;

      if (!is_valid_container_pid(pids[i]))
        continue;

      char cname[256] = {0};
      if (build_proc_root_path(pids[i], FORK_MARKER "/name", path,
                               sizeof(path)) < 0)
        continue;
      if (read_file(path, cname, sizeof(cname)) <= 0)
        continue;
      cname[strcspn(cname, "\n")] = '\0';

      if (count >= cap) {
        if (cap > 8192) {
          return -1;
        }
        cap *= 2;
        struct container_info *tmp =
            realloc(containers, (size_t)cap * sizeof(struct container_info));
        if (!tmp) {
          return -1;
        }
        containers = tmp;
      }

      size_t nlen = strlen(cname);
      if (nlen >= sizeof(containers[count].name))
        nlen = sizeof(containers[count].name) - 1;
      memcpy(containers[count].name, cname, nlen);
      containers[count].name[nlen] = '\0';
      containers[count].pid = pids[i];
      if (nlen > max_name_len)
        max_name_len = nlen;
      count++;
    }


    if (count == 0) {
      printf("\n(No containers running)\n\n");
      return 0;
    }

    if (cfg->format_output) {
      printf("TOTAL_CONTAINERS=%d\n", totalcount);
      printf("RUN_CONTAINERS=%d\n", count);

      for (int i = 0; i < count; i++) {
        printf("CONT_%s=%d\n", containers[i].name, containers[i].pid);
      }

      printf("\n");
    } else {
      if (max_name_len > 60)
        max_name_len = 60;

      printf("\n");
      printf("┌");
      for (size_t i = 0; i < max_name_len + 2; i++)
        printf("─");
      printf("┬");
      for (size_t i = 0; i < 10; i++)
        printf("─");
      printf("┐\n");
      printf("│ %-*s │ %-8s │\n", (int)max_name_len, "NAME", "PID");
      printf("├");
      for (size_t i = 0; i < max_name_len + 2; i++)
        printf("─");
      printf("┼");
      for (size_t i = 0; i < 10; i++)
        printf("─");
      printf("┤\n");

      for (int i = 0; i < count; i++) {
        printf("│ %-*s │ %-8d │\n", (int)max_name_len, containers[i].name,
               containers[i].pid);
      }

      printf("└");
      for (size_t i = 0; i < max_name_len + 2; i++)
        printf("─");
      printf("┴");
      for (size_t i = 0; i < 10; i++)
        printf("─");
      printf("┘\n");
      printf("\n");
    }
  } else {
    printf("\n(No containers running)\n\n");
  }

  return 0;
}
