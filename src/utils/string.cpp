#include "asc.h"

void safe_strncpy(char *dst, const char *src, const size_t size) {
  if (!dst || size == 0)
    return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  const size_t len = strlen(src);
  if (len >= size) {
    log_warn("字符串截断警告: src='%s' (len=%zu) 至 size=%zu", src, len,
             size);
  }
  snprintf(dst, size, "%s", src);
}

fs::path resolve_path_arg(const fs::path& path) {
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

void format_uptime(const long uptime_sec, char *buf, const size_t size) {
  if (uptime_sec < 0) {
    safe_strncpy(buf, "未知", size);
    return;
  }

  const long d = uptime_sec / 86400;
  const long h = (uptime_sec % 86400) / 3600;
  const long m = (uptime_sec % 3600) / 60;
  const long s = uptime_sec % 60;

  std::string res;
  if (d > 0) res += std::to_string(d) + "d ";
  if (h > 0 || d > 0) res += std::to_string(h) + "h ";
  if (m > 0 || h > 0 || d > 0) res += std::to_string(m) + "m ";
  res += std::to_string(s) + "s";

  safe_strncpy(buf, res.c_str(), size);
}

static bool validate_container_name(std::string_view name, size_t max_len = 256) {
    if (name.empty() || name.size() > max_len) return false;

    for (char ch : name) {
        // 严格限定在 [0-9A-Za-z_]
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= 'a' && ch <= 'z') ||
              ch == '_')) {
            return false;
        }
    }
    return true;
}

int reject_container_name(const std::string& name) {
  if (!validate_container_name(name)) {
    log_error("非法的容器名称 '%s'。", name.c_str());
    return -1;
  }
  return 0;
}

void format_privileged_mask(const int mask, char *buf, const size_t size) {
  if (size == 0)
    return;
  buf[0] = '\0';

  if (mask <= 0)
    return;

  if (mask == PRIV_FULL) {
    safe_strncpy(buf, "full", size);
    return;
  }

  bool first = true;
  const struct {
    int flag;
    const char *name;
  } flags[] = {
    {PRIV_NOMASK, "nomask"},
    {PRIV_NOCAPS, "nocaps"},
    {PRIV_NOSEC,  "noseccomp"},
    {PRIV_SHARED, "shared"},
  };

  size_t pos = 0;
  for (const auto &f : flags) {
    if (mask & f.flag) {
      const int n = snprintf(buf + pos, size - pos, "%s%s",
                              first ? "" : ",", f.name);
      if (n > 0)
        pos += static_cast<size_t>(n);
      first = false;
    }
  }
}
