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

void sanitize_container_name(const char *name, char *out, const size_t size) {
  size_t i;
  for (i = 0; i < size - 1 && name[i] != '\0'; i++)
    out[i] = name[i] == ' ' ? '-' : name[i];
  out[i] = '\0';
}

char *resolve_path_arg(const char *path) {
  // 拦截空路径
  if (!path || !*path)
    return strdup("");

  std::string expanded_path = path;

  // 1. 使用 wordexp 进行安全的 Shell 路径展开（支持 ~ 和 环境变量）
  wordexp_t we;
  // 【安全关键】必须使用 WRDE_NOCMD 标志，禁止命令执行替换，防止命令注入风险
  if (wordexp(path, &we, WRDE_NOCMD) == 0) {
    if (we.we_wordc > 0 && we.we_wordv[0]) {
      expanded_path = we.we_wordv[0];
    }
    wordfree(&we);
  }

  // 2. 现代化路径规范处理
  std::error_code ec;
  fs::path p(expanded_path);
  fs::path abs_path;

  // weakly_canonical 会智能将其转为绝对路径，并解析沿途已存在的符号链接
  // 即使路径末尾的几个层级尚未在磁盘上创建，它也能优雅处理
  // 完美替代原始繁琐的 getcwd/realpath 回退逻辑
  abs_path = fs::weakly_canonical(p, ec);
  if (ec) {
    // 遇到极端无权限访问情况时的回退：纯字面量绝对路径转换
    abs_path = fs::absolute(p, ec);
  }

  std::string result = abs_path.string();

  // 3. 剥离末尾冗余斜杠，统一规范 (保持根目录 "/" 独立)
  while (result.length() > 1 && result.back() == '/') {
    result.pop_back();
  }

  // 4. 返回兼容老代码架构的 C-style 分配器堆字符串
  return strdup(result.c_str());
}

void format_uptime(const long uptime_sec, char *buf, const size_t size) {
  if (uptime_sec < 0) {
    safe_strncpy(buf, "未知", size);
    return;
  }

  const int days = uptime_sec / 86400;
  const int hours = uptime_sec % 86400 / 3600;
  const int mins = uptime_sec % 3600 / 60;
  const int secs = uptime_sec % 60;

  char tmp[128] = "";
  int pos = 0;

  if (days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dd ", days);
  if (hours > 0 || days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dh ", hours);
  if (mins > 0 || hours > 0 || days > 0)
    pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%dm ", mins);
  snprintf(tmp + pos, sizeof(tmp) - pos, "%ds", secs);

  safe_strncpy(buf, tmp, size);
}

int validate_container_name(const char *name) {
  if (!name || !name[0])
    return 0;

  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  const size_t len = strlen(name);
  if (len >= 256)
    return 0;

  for (size_t i = 0; i < len; i++) {
    const unsigned char c = static_cast<unsigned char>(name[i]);
    if (!(isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' '))
      return 0;
  }

  return 1;
}

int reject_container_name(const char *name) {
  if (!validate_container_name(name)) {
    log_error("非法的容器名称 '%s'。", name);
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
    {PRIV_UNFILT, "unfiltered-dev"},
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

void format_size(const long long bytes, char *buf, const size_t sz) {
  if (bytes <= 0) {
    snprintf(buf, sz, "N/A");
    return;
  }
  static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  int u = 0;
  double d = static_cast<double>(bytes);
  while (d >= 1024 && u < 4) {
    d /= 1024;
    u++;
  }
  snprintf(buf, sz, "%.2f %s", d, units[u]);
}