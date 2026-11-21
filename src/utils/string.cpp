#include <algorithm>
#include <cctype>
#include <stddef.h>
#include <string_view>

#include "utils/log.h"
#include "utils/string.h"

static constexpr bool validate_container_name(std::string_view name,
                                              size_t max_len = 256) {
  if (name.empty() || name.size() > max_len)
    return false;

  return std::ranges::all_of(name, [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
  });
}

int reject_container_name(std::string_view name) {
  if (!validate_container_name(name)) {
    log_error("非法的容器名称 '{}'。", name);
    return -1;
  }
  return 0;
}