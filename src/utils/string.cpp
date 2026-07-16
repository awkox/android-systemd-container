#include "asc.h"

fs::path resolve_path_arg(const fs::path &path) {
    if (path.empty()) return "";

    std::string expanded_path = path;
    wordexp_t we;
    if (wordexp(path.c_str(), &we, WRDE_NOCMD) == 0) {
        if (we.we_wordc > 0 && we.we_wordv[0]) {
            expanded_path = we.we_wordv[0];
        }
        wordfree(&we);
    }

    std::error_code ec;
    fs::path abs_path = fs::weakly_canonical(expanded_path, ec);
    if (ec) {
        abs_path = fs::absolute(expanded_path, ec);
    }
    return abs_path.lexically_normal();
}

static bool validate_container_name(std::string_view name, size_t max_len = 256) {
  if (name.empty() || name.size() > max_len) return false;

  return std::ranges::all_of(name, [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
  });
}

int reject_container_name(const std::string &name) {
  if (!validate_container_name(name)) {
    log_error("非法的容器名称 '%s'。", name.c_str());
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