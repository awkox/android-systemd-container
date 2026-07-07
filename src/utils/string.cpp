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
  // 即使路径末尾的几个层级尚未在磁盘上创建，它也能优雅处理，完美替代原始繁琐的 getcwd/realpath 回退逻辑
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

static const struct {
  const char *opt;
} path_opts[] = {
  {"--config"},
  {"-C"},
  {nullptr},
};

void resolve_argv_paths(const int argc, char **argv) {
  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];
    if (!arg || arg[0] != '-') 
      continue;

    for (int j = 0; path_opts[j].opt; j++) {
      const char *opt = path_opts[j].opt;
      const size_t olen = strlen(opt);

      if (strncmp(arg, opt, olen) == 0 && arg[olen] == '=') {
        const char *val = arg + olen + 1;
        if (!*val || val[0] == '/')
          break; 
        auto_free char *resolved = resolve_path_arg(val);
        if (resolved) {
          char *new_arg = static_cast<char *>(malloc(olen + 1 + strlen(resolved) + 1));
          if (new_arg) {
            memcpy(new_arg, opt, olen);
            new_arg[olen] = '=';
            strcpy(new_arg + olen + 1, resolved);
            argv[i] = new_arg; 
          }
        }
        break;
      }

      if (strcmp(arg, opt) == 0 && i + 1 < argc) {
        const char *val = argv[i + 1];
        if (!val || !*val ||val[0] == '/')
          continue;
        char *resolved = resolve_path_arg(val);
        if (resolved)
          argv[i + 1] = resolved; 
        break;
      }
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