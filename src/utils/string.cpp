#include <stddef.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>

#include "utils/string.h"
#include "utils/log.h"
#include "common.h"

static constexpr bool validate_container_name(std::string_view name, size_t max_len = 256) {
  if (name.empty() || name.size() > max_len) return false;

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

std::string format_privileged_mask(const int mask) {
    if (mask == PRIV_FULL) return "full";

    std::string result;
    // 按需调整标志列表即可
    constexpr std::pair<int, std::string_view> flags[] = {
        {PRIV_NOMASK, "nomask"},
        {PRIV_NOCAPS, "nocaps"},
        {PRIV_NOSEC,  "noseccomp"},
    };

    for (const auto &[flag, name] : flags) {
        if (mask & flag) {
            if (!result.empty()) result += ',';
            result += name;
        }
    }

    return result;
}