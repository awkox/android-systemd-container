/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* Forward declarations */
static void add_unknown_line(struct config *cfg, const char *line);

/* ---------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------------*/

static char *trim_whitespace(char *str) {
  while (isspace((unsigned char)*str))
    str++;
  if (*str == 0)
    return str;

  char *end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;

  *(end + 1) = 0;
  return str;
}

/* Strict boolean parser: accepts 0/1, true/false, yes/no, on/off */
static int parse_bool(const char *val) {
  if (!val)
    return 0;

  if (strcasecmp(val, "1") == 0)
    return 1;

  if (strcasecmp(val, "0") == 0)
    return 0;

  return 0;
}

/* Safe positive integer parser: uses strtoll with full error checking.
 * Returns -1 on any error (overflow, empty, non-numeric, negative). */
static long long parse_ll_positive(const char *val) {
  if (!val || !*val)
    return -1;
  char *end;
  errno = 0;
  long long v = strtoll(val, &end, 10);
  if (errno || end == val || *end != '\0' || v <= 0)
    return -1;
  return v;
}

void parse_privileged(const char *value, struct config *cfg) {
  if (!value)
    return;

  /* Reset first so removing flags from config takes effect on reload */
  cfg->privileged_mask = 0;

  char copy[1024];
  safe_strncpy(copy, value, sizeof(copy));

  char *saveptr;
  char *token = strtok_r(copy, ",", &saveptr);

  while (token) {
    char *t = trim_whitespace(token);
    if (strcasecmp(t, "nomask") == 0)
      cfg->privileged_mask |= PRIV_NOMASK;
    else if (strcasecmp(t, "nocaps") == 0)
      cfg->privileged_mask |= PRIV_NOCAPS;
    else if (strcasecmp(t, "noseccomp") == 0)
      cfg->privileged_mask |= PRIV_NOSEC;
    else if (strcasecmp(t, "shared") == 0)
      cfg->privileged_mask |= PRIV_SHARED;
    else if (strcasecmp(t, "unfiltered-dev") == 0)
      cfg->privileged_mask |= PRIV_UNFILTERED;
    else if (strcasecmp(t, "full") == 0)
      cfg->privileged_mask |= PRIV_FULL;

    token = strtok_r(NULL, ",", &saveptr);
  }
}

static void parse_bind_mounts(const char *value, struct config *cfg) {
  if (!value)
    return;

  char copy[4096];
  safe_strncpy(copy, value, sizeof(copy));

  char *saveptr;
  char *token = strtok_r(copy, ",", &saveptr);

  while (token) {
    char *sep = strchr(token, ':');
    if (sep) {
      *sep = '\0';
      const char *src_raw = trim_whitespace(token);
      char *rest = sep + 1;

      /* Check for optional :ro suffix after dest */
      int ro = 0;
      char *flag_sep = strchr(rest, ':');
      if (flag_sep) {
        *flag_sep = '\0';
        ro = (strcmp(trim_whitespace(flag_sep + 1), "ro") == 0) ? 1 : 0;
      }
      const char *dest_raw = trim_whitespace(rest);

      char *src_exp = resolve_path_arg(src_raw);
      char *dest_exp = resolve_path_arg(dest_raw);
      const char *src = src_exp ? src_exp : src_raw;
      const char *dest = dest_exp ? dest_exp : dest_raw;

      /* Validate before storing - caller's responsibility, same as CLI path */
      if (!validate_bind_destination(dest)) {
        log_warn("Skipping unsafe bind destination '%s' from config.", dest);
      } else {
        config_add_bind(cfg, src, dest, ro);
      }
      free(src_exp);
      free(dest_exp);
    }
    token = strtok_r(NULL, ",", &saveptr);
  }
}

int config_add_bind(struct config *cfg, const char *src, const char *dest,
                    int ro) {
  if (!src || !dest || src[0] == '\0' || dest[0] == '\0')
    return 0;
  /* Defensive: callers must pre-validate; this is a last-resort assert */
  if (!validate_bind_destination(dest))
    return -1;

  /* Check for duplication */
  for (int i = 0; i < cfg->bind_count; i++) {
    if (strcmp(cfg->binds[i].src, src) == 0 &&
        strcmp(cfg->binds[i].dest, dest) == 0) {
      return 0; /* Already exists, skip */
    }
  }

  /* Grow the array if needed */
  if (cfg->bind_count >= cfg->bind_capacity) {
    int old_cap = cfg->bind_capacity;
    int new_cap;

    if (old_cap == 0) {
      new_cap = BIND_INITIAL_CAP;
    } else {
      /* Check for integer overflow */
      if (old_cap > INT_MAX / 2)
        return -1;
      new_cap = old_cap * 2;
    }

    /* Check allocation size won't overflow */
    size_t alloc_size = (size_t)new_cap * sizeof(*cfg->binds);
    if (alloc_size / sizeof(*cfg->binds) != (size_t)new_cap)
      return -1;

    struct bind_mount *new_binds = realloc(cfg->binds, alloc_size);
    if (!new_binds)
      return -1;

    /* Zero the newly allocated portion */
    memset(new_binds + old_cap, 0,
           (size_t)(new_cap - old_cap) * sizeof(*new_binds));

    cfg->binds = new_binds;
    cfg->bind_capacity = new_cap;
  }

  safe_strncpy(cfg->binds[cfg->bind_count].src, src,
               sizeof(cfg->binds[cfg->bind_count].src));
  safe_strncpy(cfg->binds[cfg->bind_count].dest, dest,
               sizeof(cfg->binds[cfg->bind_count].dest));
  cfg->binds[cfg->bind_count].ro = ro;
  cfg->bind_count++;
  return 1;
}

/*
 * IMPORTANT: free_config_binds must NOT free unknown lines.
 * The --reset path in main.c saves unknown_head/tail pointers, calls this
 * function, then memset's the struct, then restores the saved pointers.
 * If we free unknown lines here, the restored pointers dangle → SIGSEGV.
 *
 * Unknown lines are freed separately via free_config_unknown_lines().
 */

void free_config_binds(struct config *cfg) {

  if (!cfg->binds)
    return;
  free(cfg->binds);
  cfg->binds = NULL;
  cfg->bind_count = 0;
  cfg->bind_capacity = 0;
}

/* ---------------------------------------------------------------------------
 * Core Implementation
 * ---------------------------------------------------------------------------*/

int config_load(const char *config_path, struct config *cfg) {
  FILE *f = fopen(config_path, "re");
  if (!f) {
    if (errno == ENOENT) {
      cfg->config_file_existed = 0;
      return 0; /* Optional config */
    }
    return -1;
  }

  /* Clear existing unknown lines to avoid duplication on re-load */
  free_config_unknown_lines(cfg);

  cfg->config_file_existed = 1;

  char line[2048];

  while (fgets(line, sizeof(line), f)) {
    char line_copy[2048];
    safe_strncpy(line_copy, line, sizeof(line_copy));
    char *trimmed = trim_whitespace(line_copy);

    if (trimmed[0] == '#' || trimmed[0] == '\0')
      continue;

    char *equals = strchr(trimmed, '=');
    if (!equals) {
      continue;
    }

    *equals = '\0';
    char *key = trim_whitespace(trimmed);
    char *val = trim_whitespace(equals + 1);

    if (strcmp(key, "name") == 0) {
      if (validate_container_name(val))
        safe_strncpy(cfg->container_name, val, sizeof(cfg->container_name));
      else
        log_warn("config: ignoring invalid container name '%s'", val);
    } else if (strcmp(key, "rootfs_path") == 0) {
      safe_strncpy(cfg->rootfs_img_path, val, sizeof(cfg->rootfs_img_path));
    } else if (strcmp(key, "img_mount_point") == 0) {
      safe_strncpy(cfg->img_mount_point, val, sizeof(cfg->img_mount_point));
    } else if (strcmp(key, "enable_hw_access") == 0) {
      cfg->hw_access = parse_bool(val);
    } else if (strcmp(key, "enable_gpu_mode") == 0) {
      cfg->gpu_mode = parse_bool(val);
    } else if (strcmp(key, "volatile_mode") == 0) {
      cfg->volatile_mode = parse_bool(val);
    } else if (strcmp(key, "force_cgroupv1") == 0) {
      cfg->force_cgroupv1 = parse_bool(val);
    } else if (strcmp(key, "block_nested_ns") == 0) {
      cfg->block_nested_ns = parse_bool(val);
    } else if (strcmp(key, "memory_limit") == 0) {
      long long v = parse_ll_positive(val);
      if (v > 0)
        cfg->memory_limit = v;
      else
        log_warn("config: ignoring invalid memory_limit '%s'", val);
    } else if (strcmp(key, "cpu_quota") == 0) {
      long long v = parse_ll_positive(val);
      if (v > 0)
        cfg->cpu_quota = v;
      else
        log_warn("config: ignoring invalid cpu_quota '%s'", val);
    } else if (strcmp(key, "cpu_period") == 0) {
      long long v = parse_ll_positive(val);
      if (v > 0)
        cfg->cpu_period = v;
      else
        log_warn("config: ignoring invalid cpu_period '%s'", val);
    } else if (strcmp(key, "pids_limit") == 0) {
      long long v = parse_ll_positive(val);
      if (v > 0)
        cfg->pids_limit = v;
      else
        log_warn("config: ignoring invalid pids_limit '%s'", val);
    } else if (strcmp(key, "privileged") == 0) {
      parse_privileged(val, cfg);
    } else if (strcmp(key, "custom_init") == 0) {
      if (val[0] != '/')
        log_warn("config: ignoring non-absolute custom_init path '%s'", val);
      else if (strchr(val, ' '))
        log_warn("config: ignoring custom_init path with spaces '%s'", val);
      else
        safe_strncpy(cfg->custom_init, val, sizeof(cfg->custom_init));
    } else if (strcmp(key, "bind_mounts") == 0) {
      parse_bind_mounts(val, cfg);
    } else if (strcmp(key, "uuid") == 0) {
      safe_strncpy(cfg->uuid, val, sizeof(cfg->uuid));
    } else if (strcmp(key, "net_mode") == 0) {
      if (strcmp(val, "none") == 0) {
        cfg->net_mode = NET_NONE;
      } else if (strcmp(val, "host") == 0) {
        cfg->net_mode = NET_HOST;
      } else {
        log_warn(
            "Unknown network mode '%s' in config file. Defaulting to 'host'.",
            val);
        cfg->net_mode = NET_HOST;
      }
    } else {
      /* Unknown key - preserve verbatim so Android App metadata
       * (run_at_boot, use_sparse_image, sparse_image_size_gb, etc.)
       * survives config_save() unchanged. */
      add_unknown_line(cfg, line);
    }
  }

  fclose(f);
  return 0;
}

/* Internal helper to add a raw line to the unknown list */
static void add_unknown_line(struct config *cfg, const char *line) {
  struct config_line *node = malloc(sizeof(*node));
  if (!node)
    return;
  safe_strncpy(node->line, line, sizeof(node->line));
  node->next = NULL;
  if (!cfg->unknown_head) {
    cfg->unknown_head = cfg->unknown_tail = node;
  } else {
    cfg->unknown_tail->next = node;
    cfg->unknown_tail = node;
  }
}

void free_config_unknown_lines(struct config *cfg) {
  struct config_line *curr = cfg->unknown_head;
  while (curr) {
    struct config_line *next = curr->next;
    free(curr);
    curr = next;
  }
  cfg->unknown_head = cfg->unknown_tail = NULL;
}

void config_free(struct config *cfg) {
  free_config_binds(cfg);
  free_config_unknown_lines(cfg);
}

static void config_serialize_known(FILE *f, struct config *cfg) {
  fprintf(f, "# " PROJECT_NAME " Container Configuration\n");
  fprintf(f, "# Generated automatically - Changes may be overwritten\n\n");

  /* Write managed keys */
  if (cfg->container_name[0])
    fprintf(f, "name=%s\n", cfg->container_name);

  if (cfg->rootfs_img_path[0]) {
    char *abs_path = resolve_path_arg(cfg->rootfs_img_path);
    fprintf(f, "rootfs_path=%s\n", abs_path ? abs_path : cfg->rootfs_img_path);
    free(abs_path);
  }

  if (cfg->img_mount_point[0])
    fprintf(f, "img_mount_point=%s\n", cfg->img_mount_point);

  fprintf(f, "enable_hw_access=%d\n", cfg->hw_access);
  fprintf(f, "enable_gpu_mode=%d\n", cfg->gpu_mode);
  fprintf(f, "volatile_mode=%d\n", cfg->volatile_mode);
  fprintf(f, "force_cgroupv1=%d\n", cfg->force_cgroupv1);
  fprintf(f, "block_nested_ns=%d\n", cfg->block_nested_ns);
  if (cfg->memory_limit > 0)
    fprintf(f, "memory_limit=%lld\n", cfg->memory_limit);
  if (cfg->cpu_quota > 0)
    fprintf(f, "cpu_quota=%lld\n", cfg->cpu_quota);
  if (cfg->cpu_period > 0)
    fprintf(f, "cpu_period=%lld\n", cfg->cpu_period);
  if (cfg->pids_limit > 0)
    fprintf(f, "pids_limit=%lld\n", cfg->pids_limit);

  if (cfg->privileged_mask > 0) {
    fprintf(f, "privileged=");
    int first = 1;
    if (cfg->privileged_mask == PRIV_FULL) {
      fprintf(f, "full");
    } else {
      if (cfg->privileged_mask & PRIV_NOMASK) {
        fprintf(f, "%snomask", first ? "" : ",");
        first = 0;
      }
      if (cfg->privileged_mask & PRIV_NOCAPS) {
        fprintf(f, "%snocaps", first ? "" : ",");
        first = 0;
      }
      if (cfg->privileged_mask & PRIV_NOSEC) {
        fprintf(f, "%snoseccomp", first ? "" : ",");
        first = 0;
      }
      if (cfg->privileged_mask & PRIV_SHARED) {
        fprintf(f, "%sshared", first ? "" : ",");
        first = 0;
      }
      if (cfg->privileged_mask & PRIV_UNFILTERED) {
        fprintf(f, "%sunfiltered-dev", first ? "" : ",");
        first = 0;
      }
    }
    fprintf(f, "\n");
  }

  if (cfg->net_mode == NET_NONE) {
    fprintf(f, "net_mode=none\n");
  } else {
    fprintf(f, "net_mode=host\n");
  }

  if (cfg->uuid[0])
    fprintf(f, "uuid=%s\n", cfg->uuid);

  if (cfg->custom_init[0]) {
    char *abs_path = resolve_path_arg(cfg->custom_init);
    fprintf(f, "custom_init=%s\n", abs_path ? abs_path : cfg->custom_init);
    free(abs_path);
  }

  if (cfg->bind_count > 0) {
    fprintf(f, "bind_mounts=");
    for (int i = 0; i < cfg->bind_count; i++) {
      char *abs_src = resolve_path_arg(cfg->binds[i].src);
      char *abs_dest = resolve_path_arg(cfg->binds[i].dest);
      fprintf(f, "%s:%s%s%s", abs_src ? abs_src : cfg->binds[i].src,
              abs_dest ? abs_dest : cfg->binds[i].dest,
              cfg->binds[i].ro ? ":ro" : "",
              (i < cfg->bind_count - 1) ? "," : "");
      free(abs_src);
      free(abs_dest);
    }
    fprintf(f, "\n");
  }
}

int config_save(const char *config_path, struct config *cfg) {
  /* Sort bind mounts before saving so they are persisted in a sane order. */
  sort_bind_mounts(cfg);

  /* Compare new config with existing disk configuration to avoid redundant
   * writes */
  struct config disk_cfg = {0};
  struct stat st;
  int is_equal = 0;
  if (stat(config_path, &st) == 0) {
    if (config_load(config_path, &disk_cfg) == 0) {
      sort_bind_mounts(&disk_cfg);

      char *buf_cfg = NULL;
      size_t size_cfg = 0;
      char *buf_disk = NULL;
      size_t size_disk = 0;
      FILE *f_cfg = open_memstream(&buf_cfg, &size_cfg);
      FILE *f_disk = open_memstream(&buf_disk, &size_disk);

      if (f_cfg && f_disk) {
        config_serialize_known(f_cfg, cfg);
        config_serialize_known(f_disk, &disk_cfg);
        fclose(f_cfg);
        fclose(f_disk);
        if (size_cfg == size_disk && memcmp(buf_cfg, buf_disk, size_cfg) == 0) {
          is_equal = 1;
        }
      } else {
        if (f_cfg)
          fclose(f_cfg);
        if (f_disk)
          fclose(f_disk);
      }
      free(buf_cfg);
      free(buf_disk);
      free_config_binds(&disk_cfg);
      free_config_unknown_lines(&disk_cfg);

      if (is_equal) {
        if (!cfg->config_file_existed) {
          cfg->config_file_existed = 1;
        }
        return 0;
      }
    }
  }

  char temp_path[PATH_MAX];
  snprintf(temp_path, sizeof(temp_path), "%s.tmp", config_path);

  /* Step 2: Write all configurations to temporary file */
  FILE *f_out = fopen(temp_path, "we");
  if (!f_out)
    return -1;

  config_serialize_known(f_out, cfg);

  /* Step 3: Append preserved keys (Android App Config) from memory */
  if (cfg->unknown_head) {
    struct config_line *node = cfg->unknown_head;
    while (node) {
      fprintf(f_out, "%s", node->line);
      node = node->next;
    }
  }

  fclose(f_out);

  /* Step 4: Atomic rename commit */
  if (rename(temp_path, config_path) < 0) {
    unlink(temp_path);
    return -1;
  }

  if (!cfg->config_file_existed) {
    cfg->config_file_existed = 1;
  }
  return 0;
}

char *config_auto_path(const char *rootfs_path) {
  if (!rootfs_path || rootfs_path[0] == '\0')
    return NULL;

  char temp[PATH_MAX];
  safe_strncpy(temp, rootfs_path, sizeof(temp));

  char *dir = dirname(temp);
  char *final_path = malloc(PATH_MAX);
  if (final_path) {
    if (strcmp(dir, "/") == 0)
      snprintf(final_path, PATH_MAX, "/container.config");
    else
      snprintf(final_path, PATH_MAX, "%s/container.config", dir);
  }

  return final_path;
}

int config_load_by_name(const char *name, struct config *cfg) {
  if (!name || name[0] == '\0')
    return -1;
  if (!validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  char config_path[PATH_MAX];
  snprintf(config_path, sizeof(config_path),
           "%s/" RUNTIME_CONFIG_SUBDIR "/%s/container.config",
           get_runtime_dir(), safe_name);

  return config_load(config_path, cfg);
}

int config_save_by_name(const char *name, struct config *cfg) {
  if (!name || name[0] == '\0')
    return -1;
  if (!validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  char container_dir[PATH_MAX];
  snprintf(container_dir, sizeof(container_dir),
           "%s/" RUNTIME_CONFIG_SUBDIR "/%s", get_runtime_dir(), safe_name);
  mkdir_p(container_dir, 0755);

  char config_path[PATH_MAX];
  snprintf(config_path, sizeof(config_path), "%.3800s/container.config",
           container_dir);

  return config_save(config_path, cfg);
}
