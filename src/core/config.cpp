#include <fstream>
#include <string>
#include <algorithm>
#include <ranges>
#include "common.h"
#include "core/config.h"
#include "utils/log.h"

namespace asc::core {

namespace {

// 使用 std::string_view 实现零拷贝的 trim，安全且高效
std::string_view trim_whitespace(std::string_view sv) {
  sv.remove_prefix(std::min(sv.find_first_not_of(" \t\r\n"), sv.size()));
  if (!sv.empty()) {
    sv.remove_suffix(sv.size() - sv.find_last_not_of(" \t\r\n") - 1);
  }
  return sv;
}

constexpr bool parse_bool(std::string_view val) {
  return val == "1";
}

int parse_privileged(std::string_view value) {
  int mask = 0;
  for (const auto word_range : value | std::views::split(',')) {
    std::string_view token = trim_whitespace(std::string_view(word_range));
    if (token == "nomask") mask |= PRIV_NOMASK;
    else if (token == "nocaps") mask |= PRIV_NOCAPS;
    else if (token == "noseccomp") mask |= PRIV_NOSEC;
    else if (token == "full") mask |= PRIV_FULL;
  }
  return mask;
}

}

int config_load(const char *config_path, asc::conf &conf) {
  std::ifstream file(config_path);
  if (!file) return -1;

  std::string line;
  while (std::getline(file, line)) {
    std::string_view trimmed = trim_whitespace(line);

    // 忽略空行和注释
    if (trimmed.empty() || trimmed.front() == '#')
      continue;

    auto equals = trimmed.find('=');
    if (equals == std::string_view::npos)
      continue;

    // 分割键值对，并对两边执行 trim
    std::string_view key = trim_whitespace(trimmed.substr(0, equals));
    std::string_view val = trim_whitespace(trimmed.substr(equals + 1));

    if (key == "rootfs_path") {
      conf.rootfs_img_path = val;
    } else if (key == "block_nested_ns") {
      conf.block_nested_ns = parse_bool(val);
    } else if (key == "isolation_network") {
      conf.isolation_network = parse_bool(val);
    } else if (key == "privileged") {
      conf.privileged_mask = parse_privileged(val);
    } else if (key == "custom_init") {
      if (val.find(' ') != std::string_view::npos)
        log_warn("配置警告: 忽略包含空格的 custom_init 路径 '{}'", val);
      else
        conf.custom_init = val;
    } else {
      log_warn("配置警告: 忽略未知的配置键 '{}'", key);
    }
  }

  return 0;
}

}