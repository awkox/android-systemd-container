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
  if (!path || !*path)
    return strdup("");

  const char *p = path;

  if (p[0] == '~' && (p[1] == '/' || p[1] == '\0')) {
    const char *home = getenv("HOME");
    if (home) {
      const size_t hlen = strlen(home);
      const size_t plen = strlen(p + 1);
      auto_free char *to_free = static_cast<char *>(malloc(hlen + plen + 1));
      if (to_free) {
        memcpy(to_free, home, hlen);
        memcpy(to_free + hlen, p + 1, plen + 1);
        p = to_free;
      }
    }
  }

  if (p[0] == '/') {
    char *res = strdup(p);
    if (res) {
      size_t len = strlen(res);
      while (len > 1 && res[len - 1] == '/') {
        res[len - 1] = '\0';
        len--;
      }
    }
    return res;
  }

  char resolved[PATH_MAX];
  if (realpath(p, resolved))
    return strdup(resolved);

  const char *suffix = p;
  while (suffix[0] == '.' && suffix[1] == '/')
    suffix += 2;
  if (!*suffix) {
    char cwd[PATH_MAX];
    return strdup(getcwd(cwd, sizeof(cwd)) ? cwd : ".");
  }

  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    return strdup(p);

  const size_t clen = strlen(cwd);
  const size_t plen = strlen(suffix);
  if (clen + 1 + plen >= PATH_MAX)
    return strdup(p);

  char *out = static_cast<char *>(malloc(clen + 1 + plen + 1));
  if (!out)
    return strdup(p);
  memcpy(out, cwd, clen);
  out[clen] = '/';
  memcpy(out + clen + 1, suffix, plen + 1); 
  return out;
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