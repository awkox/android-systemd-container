#include "asc.h"

static char *trim_whitespace(char *str) {
  while (isspace(static_cast<unsigned char>(*str)))
    str++;
  if (*str == 0)
    return str;

  char *end = str + strlen(str) - 1;
  while (end > str && isspace(static_cast<unsigned char>(*end)))
    end--;

  *(end + 1) = 0;
  return str;
}

/* 简易的布尔解析器 */
static bool parse_bool(const char *val) {
  if (!val)
    return false;

  if (strcasecmp(val, "1") == 0)
    return true;

  if (strcasecmp(val, "0") == 0)
    return false;

  return false;
}

/* 
 * 安全的正整数解析器：使用具备完整错误检查的 strtoll。
 * 若发生任何错误（溢出、为空、非数字、负数）则返回 -1。
 */
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

static int parse_privileged(std::string_view value) {
  int mask = 0;
  if (value.empty()) return mask;

  size_t start = 0, end = 0;
  while (end != std::string_view::npos) {
    end = value.find(',', start);
    std::string_view token = value.substr(start, end - start);
    start = end + 1;

    // 去除两端空格 (代替原来的 trim_whitespace)
    token.remove_prefix(std::min(token.find_first_not_of(" \t"), token.size()));
    if (!token.empty()) {
        token.remove_suffix(token.size() - token.find_last_not_of(" \t") - 1);
    }

    // 无需 strcmp，直接进行 == 对比
    if (token == "nomask") mask |= PRIV_NOMASK;
    else if (token == "nocaps") mask |= PRIV_NOCAPS;
    else if (token == "noseccomp") mask |= PRIV_NOSEC;
    else if (token == "shared") mask |= PRIV_SHARED;
    else if (token == "unfiltered-dev") mask |= PRIV_UNFILT;
    else if (token == "full") mask |= PRIV_FULL;
  }
  return mask;
}

int config_load(const fs::path& config_path, cfg_t *cfg) {
  auto_fclose FILE *f = fopen(config_path.c_str(), "re");
  if (!f) {
    if (errno == ENOENT) {
      cfg->rt.config_file_existed = false;
      return 0; /* 配置是可选的 */
    }
    return -1;
  }

  cfg->rt.config_file_existed = true;

  asc_conf_t *conf = &cfg->conf;

  char line[2048];

  while (fgets(line, sizeof(line), f)) {
    char *trimmed = trim_whitespace(line);

    if (trimmed[0] == '#' || trimmed[0] == '\0')
      continue;

    char *equals = strchr(trimmed, '=');
    if (!equals) {
      continue;
    }

    *equals = '\0';
    const char *key = trim_whitespace(trimmed);
    const char *val = trim_whitespace(equals + 1);

    if (strcmp(key, "rootfs_path") == 0) {
      safe_strncpy(conf->rootfs_img_path, val, sizeof(conf->rootfs_img_path));
    } else if (strcmp(key, "img_mount_point") == 0) {
      safe_strncpy(conf->img_mount_point, val, sizeof(conf->img_mount_point));
    } else if (strcmp(key, "block_nested_ns") == 0) {
      conf->block_nested_ns = parse_bool(val);
    } else if (strcmp(key, "memory_limit") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->memory_limit = v;
      else
        log_warn("配置警告: 忽略无效的 memory_limit '%s'", val);
    } else if (strcmp(key, "cpu_quota") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->cpu_quota = v;
      else
        log_warn("配置警告: 忽略无效的 cpu_quota '%s'", val);
    } else if (strcmp(key, "cpu_period") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->cpu_period = v;
      else
        log_warn("配置警告: 忽略无效的 cpu_period '%s'", val);
    } else if (strcmp(key, "pids_limit") == 0) {
      const long long v = parse_ll_positive(val);
      if (v > 0)
        conf->pids_limit = v;
      else
        log_warn("配置警告: 忽略无效的 pids_limit '%s'", val);
    } else if (strcmp(key, "privileged") == 0) {
      conf->privileged_mask = parse_privileged(val);
    } else if (strcmp(key, "custom_init") == 0) {
      if (val[0] != '/')
        log_warn("配置警告: 忽略非绝对路径的 custom_init '%s'", val);
      else if (strchr(val, ' '))
        log_warn("配置警告: 忽略包含空格的 custom_init 路径 '%s'", val);
      else
        safe_strncpy(conf->custom_init, val, sizeof(conf->custom_init));
    } else if (strcmp(key, "isolation_network") == 0) {
      conf->isolation_network = parse_bool(val);
    } else {
      log_warn("配置警告: 忽略未知的配置键 '%s'", key);
    }
  }
  
  return 0;
}

static void config_serialize_known(FILE *f, const asc_conf_t *conf) {
  fprintf(f, "# " PROJECT_NAME " 容器配置文件\n");
  fprintf(f, "# 此文件由程序自动生成 - 手动修改可能会被覆盖\n\n");

  /* 写入被管理的键 */
  if (conf->rootfs_img_path[0]) {
    fs::path abs_path = resolve_path_arg(conf->rootfs_img_path);
    fprintf(f, "rootfs_path=%s\n", abs_path.empty() ? conf->rootfs_img_path : abs_path.c_str());
  }

  if (conf->img_mount_point[0])
    fprintf(f, "img_mount_point=%s\n", conf->img_mount_point);

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
    char mask_str[256];
    format_privileged_mask(conf->privileged_mask, mask_str, sizeof(mask_str));
    fprintf(f, "privileged=%s\n", mask_str);
  }

  fprintf(f, "isolation_network=%d\n", conf->isolation_network);

  if (conf->custom_init[0]) {
    fprintf(f, "custom_init=%s\n", conf->custom_init);
  }
}

int config_save(const fs::path& config_path, cfg_t *cfg) {
  fs::path temp_path = config_path;
  temp_path += ".tmp";

  /* 步骤 1: 将所有配置写入临时文件 */
  FILE *f_out = fopen(temp_path.c_str(), "we");
  if (!f_out)
    return -1;

  config_serialize_known(f_out, &cfg->conf);

  fclose(f_out);

  /* 步骤 2: 通过原子重命名提交修改 */
  if (rename(temp_path.c_str(), config_path.c_str()) < 0) {
    fs::remove(temp_path);
    return -1;
  }

  if (!cfg->rt.config_file_existed) {
    cfg->rt.config_file_existed = true;
  }
  return 0;
}

int config_load_by_name(const char *name, cfg_t *cfg) {
  fs::path config_path = config_dir / name / "container.config";
  return config_load(config_path, cfg);
}

int config_save_by_name(const char *name, cfg_t *cfg) {
  fs::path container_dir = config_dir / name;
  create_directories_with_permission(container_dir);
  fs::path config_path = container_dir / "container.config";

  return config_save(config_path.c_str(), cfg);
}