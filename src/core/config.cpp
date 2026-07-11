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
  if (strcasecmp(val, "1") == 0)
    return true;

  if (strcasecmp(val, "0") == 0)
    return false;

  return false;
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
    else if (token == "full") mask |= PRIV_FULL;
  }
  return mask;
}

int config_load(const fs::path& config_path, cfg_t *cfg) {
  auto_fclose FILE *f = fopen(config_path.c_str(), "re");
  if (!f) {
    if (errno == ENOENT) {
      return 0; /* 配置是可选的 */
    }
    return -1;
  }

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
      conf->rootfs_img_path = val;
    } else if (strcmp(key, "block_nested_ns") == 0) {
      conf->block_nested_ns = parse_bool(val);
    } else if (strcmp(key, "privileged") == 0) {
      conf->privileged_mask = parse_privileged(val);
    } else if (strcmp(key, "custom_init") == 0) {
      if (val[0] != '/')
        log_warn("配置警告: 忽略非绝对路径的 custom_init '%s'", val);
      else if (strchr(val, ' '))
        log_warn("配置警告: 忽略包含空格的 custom_init 路径 '%s'", val);
      else
        conf->custom_init = val;
    } else if (strcmp(key, "isolation_network") == 0) {
      conf->isolation_network = parse_bool(val);
    } else {
      log_warn("配置警告: 忽略未知的配置键 '%s'", key);
    }
  }
  
  return 0;
}

static void config_serialize_known(FILE *f, const asc_conf_t *conf) {
  /* 写入被管理的键 */
  if (!conf->rootfs_img_path.empty()) {
    fprintf(f, "rootfs_path=%s\n", conf->rootfs_img_path.c_str());
  }

  fprintf(f, "block_nested_ns=%d\n", conf->block_nested_ns);

  if (conf->privileged_mask > 0) {
    char mask_str[256];
    format_privileged_mask(conf->privileged_mask, mask_str, sizeof(mask_str));
    fprintf(f, "privileged=%s\n", mask_str);
  }

  fprintf(f, "isolation_network=%d\n", conf->isolation_network);

  if (!conf->custom_init.empty()) {
    fprintf(f, "custom_init=%s\n", conf->custom_init.c_str());
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

  return 0;
}

int config_load_by_name(std::string_view name, cfg_t *cfg) {
  fs::path config_path = config_dir / name / "container.config";
  return config_load(config_path, cfg);
}

int config_save_by_name(std::string_view name, cfg_t *cfg) {
  fs::path container_dir = config_dir / name;
  create_directories_with_permission(container_dir);
  fs::path config_path = container_dir / "container.config";

  return config_save(config_path, cfg);
}