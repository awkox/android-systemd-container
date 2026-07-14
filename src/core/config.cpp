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

    token.remove_prefix(std::min(token.find_first_not_of(" \t"), token.size()));
    if (!token.empty()) {
      token.remove_suffix(token.size() - token.find_last_not_of(" \t") - 1);
    }

    if (token == "nomask") mask |= PRIV_NOMASK;
    else if (token == "nocaps") mask |= PRIV_NOCAPS;
    else if (token == "noseccomp") mask |= PRIV_NOSEC;
    else if (token == "full") mask |= PRIV_FULL;
  }
  return mask;
}

int config_load(const char *config_path, asc_conf_t *conf) {
  FILE *f = fopen(config_path, "re");
  if (!f) {
    return -1;
  }

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

  fclose(f);
  return 0;
}
