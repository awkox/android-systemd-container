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

/* Restore host-side metadata (config, pid, mount) from internal markers.
 * Returns 0 on success, -1 on failure. */
static int metadata_sync(const pid_t pid) {
  if (pid <= 1 || !is_valid_container_pid(pid))
    return -1;

  char path[PATH_MAX];
  char name[256] = {0};
  char mount[PATH_MAX] = {0};

  /* 1. Resolve Identity */
  build_proc_root_path(pid, FORK_MARKER "/name", path, sizeof(path));
  if (read_file(path, name, sizeof(name)) < 0)
    return -1;
  name[strcspn(name, "\n")] = '\0';
  if (reject_container_name(name) < 0)
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  /* 2. Restore Workspace Directory */
  char container_dir[PATH_MAX];
  snprintf(container_dir, sizeof(container_dir),
           "%s/" RUNTIME_CONFIG_SUBDIR "/%s", get_runtime_dir(), safe_name);
  mkdir_p(container_dir, 0755);

  /* 3. Restore Configuration */
  cfg_t recovery_cfg = {0};

  build_proc_root_path(pid, FORK_MARKER "/container.config", path,
                       sizeof(path));

  bool config_restored = false;
  if (config_load(path, &recovery_cfg) == 0) {
    snprintf(recovery_cfg.config_file, sizeof(recovery_cfg.config_file),
             "%.3800s/container.config", container_dir);
    config_restored = true;
  }

  /* 4. Read mount path from /proc/<pid>/environ */
  if (read_proc_environ(pid, "RUNTIME_MOUNT_PATH", mount, sizeof(mount)) >= 0) {
    safe_strncpy(recovery_cfg.img_mount_point, mount,
                 sizeof(recovery_cfg.img_mount_point));
  } else {
    build_proc_root_path(pid, FORK_MARKER "/mount", path, sizeof(path));
    if (read_file(path, mount, sizeof(mount)) >= 0) {
      mount[strcspn(mount, "\n")] = '\0';
      safe_strncpy(recovery_cfg.img_mount_point, mount,
                   sizeof(recovery_cfg.img_mount_point));
    }
  }

  /* 5. Persist recovered config to workspace */
  if (config_restored && access(recovery_cfg.config_file, F_OK) != 0) {
    if (config_save(recovery_cfg.config_file, &recovery_cfg) < 0) {
      log_warn("Recovery: Failed to persist configuration for PID %d", pid);
    } else {
      log_info("Recovery: Restored missing configuration for container '%s'",
               safe_name);
    }
  }

  config_free(&recovery_cfg);
  return 0;
}

int scan_containers(void) {
  log_info("Scanning system for untracked containers...");

  auto_free pid_t *pids = nullptr;
  size_t count;
  if (collect_pids(&pids, &count) < 0)
    return -1;

  /* 1. Tracked Mount Points (to detect orphaned mounts) */
  typedef char mount_path_t[PATH_MAX];
  auto_free mount_path_t *tracked_mounts =
      calloc(MAX_TRACKED_ENTRIES, sizeof(mount_path_t));
  if (!tracked_mounts) {
    return -1;
  }
  int tracked_mount_count = 0;

  /* 2. Process all running PIDs */
  int recovered_found = 0;
  for (size_t i = 0; i < count; i++) {
    const pid_t pid = pids[i];
    if (pid <= 1)
      continue;

    /* If it's a ds-fork init process, synchronize its metadata.
     * This handles both untracked containers and tracked containers
     * with missing sidecars (mount, .config). */
    if (is_valid_container_pid(pid) && is_container_init(pid)) {
      if (metadata_sync(pid) == 0) {
        recovered_found++;
      }
    }
  }

  /* 3. Get list of tracked mount points from container configs to detect
   * orphans */
  tracked_mount_count = 0;
  {
    char cdir[PATH_MAX];
    snprintf(cdir, sizeof(cdir), "%s/%s", get_runtime_dir(),
             RUNTIME_CONFIG_SUBDIR);
    auto_closedir DIR *cd = opendir(cdir);
    if (cd) {
      struct dirent *ent;
      while ((ent = readdir(cd)) != nullptr &&
             tracked_mount_count < MAX_TRACKED_ENTRIES) {
        if (ent->d_name[0] == '.')
          continue;
        char cfgpath[PATH_MAX];
        snprintf(cfgpath, sizeof(cfgpath), "%s/%s/container.config", cdir,
                 ent->d_name);
        cfg_t tmp_cfg = {0};
        if (config_load(cfgpath, &tmp_cfg) == 0) {
          if (tmp_cfg.img_mount_point[0]) {
            safe_strncpy(tracked_mounts[tracked_mount_count],
                         tmp_cfg.img_mount_point, PATH_MAX);
            tracked_mount_count++;
          }
          config_free(&tmp_cfg);
        }
      }
    }
  }

  /* 4. 扫描 /mnt/asc 中孤立的 loop 挂载 */
  int orphaned_found = 0;
  auto_closedir DIR *md = opendir(IMG_MOUNT_ROOT);
  if (md) {
    struct dirent *ent;
    while ((ent = readdir(md)) != nullptr) {
      if (ent->d_name[0] == '.')
        continue;

      char mpath[PATH_MAX];
      snprintf(mpath, sizeof(mpath), "%s/%s", IMG_MOUNT_ROOT, ent->d_name);

      if (is_mountpoint(mpath)) {
        bool is_tracked = false;
        for (int i = 0; i < tracked_mount_count; i++) {
          if (strcmp(mpath, tracked_mounts[i]) == 0) {
            is_tracked = true;
            break;
          }
        }

        if (!is_tracked) {
          log_warn("Found orphaned mount: %s, cleaning up...", mpath);
          unmount_rootfs_img(mpath, false);
          orphaned_found++;
        }
      } else {
        rmdir(mpath);
      }
    }
  }

  if (recovered_found == 0 && orphaned_found == 0)
    log_info("No untracked resources found.");
  else
    log_info("Scan complete: synchronized %d container(s), cleaned %d orphaned "
             "mount(s).",
             recovered_found, orphaned_found);

  return 0;
}
