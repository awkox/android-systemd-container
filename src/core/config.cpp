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
static constexpr bool parse_bool(std::string_view val) {
  return val == "1";
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
    std::string_view key = trim_whitespace(trimmed);
    const char *val = trim_whitespace(equals + 1);

    if (key == "rootfs_path") {
      conf->rootfs_img_path = val;
    } else if (key == "block_nested_ns") {
      conf->block_nested_ns = parse_bool(val);
    } else if (key == "privileged") {
      conf->privileged_mask = parse_privileged(val);
    } else if (key == "custom_init") {
      if (strchr(val, ' '))
        log_warn("配置警告: 忽略包含空格的 custom_init 路径 '%s'", val);
      else
        conf->custom_init = val;
    } else if (key == "isolation_network") {
      conf->isolation_network = parse_bool(val);
    } else {
      log_warn("配置警告: 忽略未知的配置键 '%s'", key.data());
    }
  }
  
  return 0;
}

static void config_serialize_known(std::ostream &out, const asc_conf_t *conf) {
  if (!conf->rootfs_img_path.empty())
    out << "rootfs_path=" << conf->rootfs_img_path.string() << '\n';
  out << "block_nested_ns=" << conf->block_nested_ns << '\n';
  if (conf->privileged_mask > 0)
    out << "privileged=" << format_privileged_mask(conf->privileged_mask) << '\n';
  out << "isolation_network=" << conf->isolation_network << '\n';
  if (!conf->custom_init.empty())
    out << "custom_init=" << conf->custom_init.string() << '\n';
}

int config_save(const fs::path& config_path, cfg_t *cfg) {
  fs::path temp_path = config_path;
  temp_path += ".tmp";
  {
    std::ofstream out(temp_path);
    if (!out) return -1;
    config_serialize_known(out, &cfg->conf);
  }
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