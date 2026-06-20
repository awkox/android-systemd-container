/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* ---------------------------------------------------------------------------
 * Workspace / Paths
 * ---------------------------------------------------------------------------*/

const char *get_runtime_dir(void) { return RUNTIME_DIR; }

const char *get_lock_dir(void) {
  static char lock_path[PATH_MAX];
  snprintf(lock_path, sizeof(lock_path), "%s/%s", get_runtime_dir(),
           RUNTIME_LOCK_SUBDIR);
  return lock_path;
}

const char *get_logs_dir(void) {
  static char logs_path[PATH_MAX];
  snprintf(logs_path, sizeof(logs_path), "%s/%s", get_runtime_dir(),
           RUNTIME_LOGS_SUBDIR);
  return logs_path;
}

int ensure_runtime(void) {
  mkdir_p(get_runtime_dir(), 0755);
  mkdir_p(get_lock_dir(), 0755);
  mkdir_p(get_logs_dir(), 0755);

  return 0;
}

/* ---------------------------------------------------------------------------
 * Container Naming
 * ---------------------------------------------------------------------------*/

int generate_container_name(const char *rootfs_path, char *name, size_t size) {
  char id[64], version[64];

  if (parse_os_release(rootfs_path, id, version, sizeof(id)) < 0) {
    /* Fallback if os-release is missing */
    safe_strncpy(name, "linux-container", size);
    return 0;
  }

  if (version[0])
    snprintf(name, size, "%s-%s", id, version);
  else
    safe_strncpy(name, id, size);

  return 0;
}

/* ---------------------------------------------------------------------------
 * PID Discovery (UUID Scan)
 * ---------------------------------------------------------------------------*/

int is_container_running(struct config *cfg, pid_t *pid_out) {
  if (cfg->uuid[0] == '\0')
    return 0;

  pid_t deep_pid = find_container_init_pid(cfg->uuid);
  if (deep_pid > 0) {
    if (pid_out)
      *pid_out = deep_pid;
    return 1;
  }

  return 0;
}

int count_running_containers(char *first_name, size_t size) {
  _cleanup_free_ pid_t *pids = NULL;
  size_t pcount = 0;
  char path[PATH_MAX];
  int running = 0;

  if (collect_pids(&pids, &pcount) < 0)
    return 0;

  for (size_t i = 0; i < pcount; i++) {
    if (build_proc_root_path(pids[i], FORK_MARKER, path, sizeof(path)) < 0)
      continue;
    if (access(path, F_OK) != 0)
      continue;

    if (!is_valid_container_pid(pids[i]))
      continue;

    char cname[256] = {0};
    if (build_proc_root_path(pids[i], FORK_MARKER "/name", path,
                             sizeof(path)) >= 0 &&
        read_file(path, cname, sizeof(cname)) > 0) {
      cname[strcspn(cname, "\n")] = '\0';
      if (running == 0 && first_name && size > 0)
        safe_strncpy(first_name, cname, size);
      running++;
    }
  }

  return running;
}

/* ---------------------------------------------------------------------------
 * UUID Scan
 * ---------------------------------------------------------------------------*/

pid_t find_container_init_pid(const char *uuid) {
  if (!uuid || uuid[0] == '\0')
    return 0;

  char marker[PATH_MAX];
  snprintf(marker, sizeof(marker), FORK_MARKER "/%s", uuid);

  _cleanup_free_ pid_t *pids = NULL;
  size_t count = 0;
  char path[PATH_MAX];

  if (collect_pids(&pids, &count) < 0)
    return 0;

  for (size_t i = 0; i < count; i++) {
    /* Fast check: does FORK_MARKER exist?
     * This avoids expensive deep path checks for host processes. */
    if (build_proc_root_path(pids[i], FORK_MARKER, path, sizeof(path)) < 0)
      continue;

    if (access(path, F_OK) == 0) {
      /* Now check for the specific UUID marker */
      build_proc_root_path(pids[i], marker, path, sizeof(path));
      if (access(path, F_OK) == 0) {
        if (is_valid_container_pid(pids[i])) {
          pid_t found = pids[i];
          return found;
        }
      }
    }
  }

  return 0;
}

int collect_active_uuids(char uuids[][UUID_LEN + 1], int max_uuids) {
  if (!uuids || max_uuids <= 0)
    return 0;

  _cleanup_free_ pid_t *pids = NULL;
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

    _cleanup_closedir_ DIR *d = opendir(path);
    if (!d)
      continue;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && found < max_uuids) {
      if (strlen(ent->d_name) != UUID_LEN)
        continue;
      /* Verify it's all hex chars -- UUID marker files are 32 hex chars */
      int is_uuid = 1;
      for (int j = 0; j < UUID_LEN; j++) {
        char c = ent->d_name[j];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
          is_uuid = 0;
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

/* ---------------------------------------------------------------------------
 * Status reporting
 * ---------------------------------------------------------------------------*/

int show_containers(struct config *cfg) {
  _cleanup_free_ struct container_info *containers = NULL;

  int count = 0;
  int cap = 32;

  /* Total tracked = folders under Containers */
  char container_dir[1024];
  snprintf(container_dir, sizeof(container_dir), "%s/%s", get_runtime_dir(),
           RUNTIME_CONFIG_SUBDIR);
  int totalcount = count_folders(container_dir);

  containers = malloc(cap * sizeof(struct container_info));
  if (!containers)
    return -1;

  /* Scan /proc for running containers */
  _cleanup_free_ pid_t *pids = NULL;
  size_t pcount = 0;
  char path[PATH_MAX];

  if (collect_pids(&pids, &pcount) >= 0) {
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

int is_container_init(pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  _cleanup_fclose_ FILE *f = fopen(path, "re");
  if (!f)
    return 0;

  char line[1024];
  int is_init = 0;
  int nspid_found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "NSpid:", 6) == 0) {
      /* NSpid line format: "NSpid: <pid1> <pid2> ... <pidN>"
       * The last value is the PID in the innermost namespace.
       * We use a robust tokenizer to avoid issues with tabs/spaces.
       * NOTE: NSpid was added in Linux 4.1. On older kernels (e.g. 3.10),
       * this line is absent and we fall back to the ns/pid inode check. */
      nspid_found = 1;
      char *p = line + 6;
      char *last_val = NULL;
      char *saveptr;
      char *token = strtok_r(p, " \t\n\r", &saveptr);
      while (token) {
        last_val = token;
        token = strtok_r(NULL, " \t\n\r", &saveptr);
      }
      if (last_val && strcmp(last_val, "1") == 0) {
        is_init = 1;
      }
      break;
    }
  }

  if (nspid_found)
    return is_init;

  /*
   * Fallback for kernels < 4.1 (e.g. 3.10) where NSpid is absent:
   * Compare the inode of /proc/<pid>/ns/pid vs /proc/1/ns/pid.
   * Available since Linux 3.8 (namespaces(7)).
   * If inodes differ, the process lives in a different PID namespace.
   * Combined with the FORK_MARKER marker check in
   * is_valid_container_pid(), this is sufficient to identify a
   * container init process.
   */
  struct stat st_pid, st_host;
  char ns_path[PATH_MAX];

  snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/pid", pid);
  if (stat(ns_path, &st_pid) < 0)
    return 0;

  if (stat("/proc/1/ns/pid", &st_host) < 0)
    return 0;

  /* Different inode == different PID namespace == process is a container init
   */
  return (st_pid.st_ino != st_host.st_ino) ? 1 : 0;
}

/* Restore host-side metadata (config, pid, mount) from internal markers.
 * Returns 0 on success, -1 on failure. */
int metadata_sync(pid_t pid) {
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
  struct config recovery_cfg = {0};

  build_proc_root_path(pid, FORK_MARKER "/container.config", path,
                       sizeof(path));

  int config_restored = 0;
  if (config_load(path, &recovery_cfg) == 0) {
    snprintf(recovery_cfg.config_file, sizeof(recovery_cfg.config_file),
             "%.3800s/container.config", container_dir);
    config_restored = 1;
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
  log_info("Scanning system for untracked " PROJECT_NAME " containers...");

  _cleanup_free_ pid_t *pids = NULL;
  size_t count;
  if (collect_pids(&pids, &count) < 0)
    return -1;

  /* 1. Tracked Mount Points (to detect orphaned mounts) */
  typedef char mount_path_t[PATH_MAX];
  _cleanup_free_ mount_path_t *tracked_mounts =
      calloc(MAX_TRACKED_ENTRIES, sizeof(mount_path_t));
  if (!tracked_mounts) {
    return -1;
  }
  int tracked_mount_count = 0;

  /* 2. Process all running PIDs */
  int recovered_found = 0;
  for (size_t i = 0; i < count; i++) {
    pid_t pid = pids[i];
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
    _cleanup_closedir_ DIR *cd = opendir(cdir);
    if (cd) {
      struct dirent *ent;
      while ((ent = readdir(cd)) != NULL &&
             tracked_mount_count < MAX_TRACKED_ENTRIES) {
        if (ent->d_name[0] == '.')
          continue;
        char cfgpath[PATH_MAX];
        snprintf(cfgpath, sizeof(cfgpath), "%s/%s/container.config", cdir,
                 ent->d_name);
        struct config tmp_cfg = {0};
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

  /* 4. Scan for orphaned loop mounts in /tmp/ds-fork/mnt */
  int orphaned_found = 0;
  _cleanup_closedir_ DIR *md = opendir(IMG_MOUNT_ROOT);
  if (md) {
    struct dirent *ent;
    while ((ent = readdir(md)) != NULL) {
      if (ent->d_name[0] == '.')
        continue;

      char mpath[PATH_MAX];
      snprintf(mpath, sizeof(mpath), "%s/%s", IMG_MOUNT_ROOT, ent->d_name);

      if (is_mountpoint(mpath)) {
        int is_tracked = 0;
        for (int i = 0; i < tracked_mount_count; i++) {
          if (strcmp(mpath, tracked_mounts[i]) == 0) {
            is_tracked = 1;
            break;
          }
        }

        if (!is_tracked) {
          log_warn("Found orphaned mount: %s, cleaning up...", mpath);
          unmount_rootfs_img(mpath, 0);
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
