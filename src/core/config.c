#include "asc.h"

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
static bool parse_bool(const char *val) {
  if (!val)
    return false;

  if (strcasecmp(val, "1") == 0)
    return true;

  if (strcasecmp(val, "0") == 0)
    return false;

  return false;
}

/* Safe positive integer parser: uses strtoll with full error checking.
 * Returns -1 on any error (overflow, empty, non-numeric, negative). */
static long long parse_ll_positive(const char *val) {
  if (!val || !*val)
    return -1;
  char *end;
  errno = 0;
  const long long v = strtoll(val, &end, 10);
  if (errno || end == val || *end != '\0' || v <= 0)
    return -1;
  return v;
}

static void parse_privileged(const char *value, asc_conf_t *conf) {
  if (!value)
    return;

  /* Reset first so removing flags from config takes effect on reload */
  conf->privileged_mask = 0;

  char copy[1024];
  safe_strncpy(copy, value, sizeof(copy));

  char *saveptr;
  char *token = strtok_r(copy, ",", &saveptr);

  while (token) {
    const char *t = trim_whitespace(token);
    if (strcasecmp(t, "nomask") == 0)
      conf->privileged_mask |= PRIV_NOMASK;
    else if (strcasecmp(t, "nocaps") == 0)
      conf->privileged_mask |= PRIV_NOCAPS;
    else if (strcasecmp(t, "noseccomp") == 0)
      conf->privileged_mask |= PRIV_NOSEC;
    else if (strcasecmp(t, "shared") == 0)
      conf->privileged_mask |= PRIV_SHARED;
    else if (strcasecmp(t, "unfiltered-dev") == 0)
      conf->privileged_mask |= PRIV_UNFILT;
    else if (strcasecmp(t, "full") == 0)
      conf->privileged_mask |= PRIV_FULL;

    token = strtok_r(nullptr, ",", &saveptr);
  }
}

int config_load(const char *config_path, cfg_t *cfg) {
  auto_fclose FILE *f = fopen(config_path, "re");
  if (!f) {
    if (errno == ENOENT) {
      cfg->rt.config_file_existed = false;
      return 0; /* Optional config */
    }
    return -1;
  }

  cfg->rt.config_file_existed = true;

  asc_conf_t *conf = &cfg->conf;

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
    const char *key = trim_whitespace(trimmed);
    const char *val = trim_whitespace(equals + 1);

    if (strcmp(key, "name") == 0) {
      if (validate_container_name(val))
        safe_strncpy(conf->container_name, val, sizeof(conf->container_name));
      else
        log_warn("config: ignoring invalid container name '%s'", val);
    } else if (strcmp(key, "rootfs_path") == 0) {
      safe_strncpy(conf->rootfs_img_path, val, sizeof(conf->rootfs_img_path));
    } else if (strcmp(key, "img_mount_point") == 0) {
      safe_strncpy(conf->img_mount_point, val, sizeof(conf->img_mount_point));
    } else if (strcmp(key, "enable_hw_access") == 0) {
      conf->hw_access = parse_bool(val);
    } else if (strcmp(key, "enable_gpu_mode") == 0) {
      conf->gpu_mode = parse_bool(val);
    } else if (strcmp(key, "volatile_mode") == 0) {
      conf->volatile_mode = parse_bool(val);
    } else if (strcmp(key, "force_cgroupv1") == 0) {
      conf->force_cgroupv1 = parse_bool(val);
    } else if (strcmp(key, "block_nested_ns") == 0) {
      conf->block_nested_ns = parse_bool(val);
    } else if (strcmp(key, "memory_limit") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->memory_limit = v;
      else
        log_warn("config: ignoring invalid memory_limit '%s'", val);
    } else if (strcmp(key, "cpu_quota") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->cpu_quota = v;
      else
        log_warn("config: ignoring invalid cpu_quota '%s'", val);
    } else if (strcmp(key, "cpu_period") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->cpu_period = v;
      else
        log_warn("config: ignoring invalid cpu_period '%s'", val);
    } else if (strcmp(key, "pids_limit") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->pids_limit = v;
      else
        log_warn("config: ignoring invalid pids_limit '%s'", val);
    } else if (strcmp(key, "privileged") == 0) {
      parse_privileged(val, conf);
    } else if (strcmp(key, "custom_init") == 0) {
      if (val[0] != '/')
        log_warn("config: ignoring non-absolute custom_init path '%s'", val);
      else if (strchr(val, ' '))
        log_warn("config: ignoring custom_init path with spaces '%s'", val);
      else
        safe_strncpy(conf->custom_init, val, sizeof(conf->custom_init));
    } else if (strcmp(key, "uuid") == 0) {
      safe_strncpy(conf->uuid, val, sizeof(conf->uuid));
    } else if (strcmp(key, "isolation_network") == 0) {
      conf->isolation_network = parse_bool(val);
    } else {
      log_warn("config: ignoring unknown key '%s'", key);
    }
  }
  
  return 0;
}

static void config_serialize_known(FILE *f, asc_conf_t *conf) {
  fprintf(f, "# " PROJECT_NAME " Container Configuration\n");
  fprintf(f, "# Generated automatically - Changes may be overwritten\n\n");

  /* Write managed keys */
  if (conf->container_name[0])
    fprintf(f, "name=%s\n", conf->container_name);

  if (conf->rootfs_img_path[0]) {
    auto_free char *abs_path = resolve_path_arg(conf->rootfs_img_path);
    fprintf(f, "rootfs_path=%s\n", abs_path ? abs_path : conf->rootfs_img_path);
  }

  if (conf->img_mount_point[0])
    fprintf(f, "img_mount_point=%s\n", conf->img_mount_point);

  fprintf(f, "enable_hw_access=%d\n", conf->hw_access);
  fprintf(f, "enable_gpu_mode=%d\n", conf->gpu_mode);
  fprintf(f, "volatile_mode=%d\n", conf->volatile_mode);
  fprintf(f, "force_cgroupv1=%d\n", conf->force_cgroupv1);
  fprintf(f, "block_nested_ns=%d\n", conf->block_nested_ns);
  if (conf->memory_limit > 0)
    fprintf(f, "memory_limit=%lld\n", conf->memory_limit);
  if (conf->cpu_quota > 0)
    fprintf(f, "cpu_quota=%lld\n", conf->cpu_quota);
  if (conf->cpu_period > 0)
    fprintf(f, "cpu_period=%lld\n", conf->cpu_period);
  if (conf->pids_limit > 0)
    fprintf(f, "pids_limit=%lld\n", conf->pids_limit);

  if (conf->privileged_mask > 0) {
    fprintf(f, "privileged=");
    if (conf->privileged_mask == PRIV_FULL) {
      fprintf(f, "full");
    } else {
      bool first = true;
      if (conf->privileged_mask & PRIV_NOMASK) {
        fprintf(f, "%snomask", first ? "" : ",");
        first = false;
      }
      if (conf->privileged_mask & PRIV_NOCAPS) {
        fprintf(f, "%snocaps", first ? "" : ",");
        first = false;
      }
      if (conf->privileged_mask & PRIV_NOSEC) {
        fprintf(f, "%snoseccomp", first ? "" : ",");
        first = false;
      }
      if (conf->privileged_mask & PRIV_SHARED) {
        fprintf(f, "%sshared", first ? "" : ",");
        first = false;
      }
      if (conf->privileged_mask & PRIV_UNFILT) {
        fprintf(f, "%sunfiltered-dev", first ? "" : ",");
        first = false;
      }
    }
    fprintf(f, "\n");
  }

  fprintf(f, "isolation_network=%d\n", conf->isolation_network);

  if (conf->uuid[0])
    fprintf(f, "uuid=%s\n", conf->uuid);

  if (conf->custom_init[0]) {
    auto_free char *abs_path = resolve_path_arg(conf->custom_init);
    fprintf(f, "custom_init=%s\n", abs_path ? abs_path : conf->custom_init);
  }
}

int config_save(const char *config_path, cfg_t *cfg) {
  /* Compare new config with existing disk configuration to avoid redundant
   * writes */
  struct stat st;
  if (stat(config_path, &st) == 0) {
    cfg_t disk_cfg = {};
    if (config_load(config_path, &disk_cfg) == 0) {
      auto_free char *buf_cfg = nullptr;
      auto_free char *buf_disk = nullptr;
      size_t size_cfg = 0;
      size_t size_disk = 0;
      FILE *f_cfg = open_memstream(&buf_cfg, &size_cfg);
      FILE *f_disk = open_memstream(&buf_disk, &size_disk);
      bool is_equal = false;

      if (f_cfg && f_disk) {
        config_serialize_known(f_cfg, &cfg->conf);
        config_serialize_known(f_disk, &disk_cfg.conf);
        fclose(f_cfg);
        fclose(f_disk);
        if (size_cfg == size_disk && memcmp(buf_cfg, buf_disk, size_cfg) == 0) {
          is_equal = true;
        }
      } else {
        if (f_cfg)
          fclose(f_cfg);
        if (f_disk)
          fclose(f_disk);
      }

      if (is_equal) {
        if (!cfg->rt.config_file_existed) {
          cfg->rt.config_file_existed = true;
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

  config_serialize_known(f_out, &cfg->conf);

  fclose(f_out);

  /* Step 4: Atomic rename commit */
  if (rename(temp_path, config_path) < 0) {
    unlink(temp_path);
    return -1;
  }

  if (!cfg->rt.config_file_existed) {
    cfg->rt.config_file_existed = true;
  }
  return 0;
}

char *config_auto_path(const char *rootfs_path) {
  if (!rootfs_path || rootfs_path[0] == '\0')
    return nullptr;

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

int config_load_by_name(const char *name, cfg_t *cfg) {
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

int config_save_by_name(const char *name, cfg_t *cfg) {
  if (!name || name[0] == '\0')
    return -1;
  if (!validate_container_name(name))
    return -1;

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  char container_dir[PATH_MAX];
  snprintf(container_dir, sizeof(container_dir),
           "%s/" RUNTIME_CONFIG_SUBDIR "/%s",
           get_runtime_dir(), safe_name);

  mkdir_p(container_dir, 0755);

  char config_path[PATH_MAX];
  snprintf(config_path, sizeof(config_path), "%.3800s/container.config",
           container_dir);

  return config_save(config_path, cfg);
}
