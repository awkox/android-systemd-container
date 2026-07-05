#include "asc.h"

void safe_strncpy(char *dst, const char *src, size_t size) {
  if (!dst || size == 0)
    return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  size_t len = strlen(src);
  if (len >= size) {
    log_warn("String truncation: src='%s' (len=%zu) to size=%zu", src, len,
             size);
  }
  snprintf(dst, size, "%s", src);
}

/* Mirrors ContainerManager.sanitizeContainerName() in the Android app.
 * Replaces spaces with dashes so directory names are consistent. */
void sanitize_container_name(const char *name, char *out, size_t size) {
  size_t i;
  for (i = 0; i < size - 1 && name[i] != '\0'; i++)
    out[i] = (name[i] == ' ') ? '-' : name[i];
  out[i] = '\0';
}

/* ---------------------------------------------------------------------------
 * Relative-path resolution
 *
 * The daemon calls chdir("/") inside daemonize(), so any relative path
 * captured from the user's CWD must be made absolute BEFORE we reach the
 * daemonize()/reexec() boundary.  resolve_argv_paths() is called once
 * in main() while CWD is still the user's directory.
 *
 * Strategy:
 *   1. Try realpath(3) - handles .., symlinks, and canonicalises the path.
 *      This works for paths that already exist on disk.
 *   2. For paths that do not exist yet (e.g. a new rootfs image being
 *      created), fall back to a plain cwd-join.  We still strip leading ./
 *      sequences so the result is always absolute.
 * ---------------------------------------------------------------------------*/
char *resolve_path_arg(const char *path) {
  if (!path || !*path)
    return strdup("");

  const char *p = path;
  auto_free char *to_free = nullptr;

  /* Handle ~/ expansion */
  if (p[0] == '~' && (p[1] == '/' || p[1] == '\0')) {
    const char *home = getenv("HOME");
    if (home) {
      size_t hlen = strlen(home);
      size_t plen = strlen(p + 1);
      to_free = malloc(hlen + plen + 1);
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

  /* Fast path: realpath handles .., symlinks, and validates existence. */
  char resolved[PATH_MAX];
  if (realpath(p, resolved))
    return strdup(resolved);

  /* Path does not exist yet - build an absolute path from the current CWD.
   * Strip leading ./ noise before joining so the result stays clean. */
  const char *suffix = p;
  while (suffix[0] == '.' && suffix[1] == '/')
    suffix += 2;
  if (!*suffix) {
    /* Input was pure "./" - resolve to CWD itself. */
    char cwd[PATH_MAX];
    return strdup(getcwd(cwd, sizeof(cwd)) ? cwd : ".");
  }

  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    return strdup(p);

  size_t clen = strlen(cwd), plen = strlen(suffix);
  if (clen + 1 + plen >= PATH_MAX)
    return strdup(p);

  char *out = malloc(clen + 1 + plen + 1);
  if (!out)
    return strdup(p);
  memcpy(out, cwd, clen);
  out[clen] = '/';
  memcpy(out + clen + 1, suffix, plen + 1); /* copies the NUL terminator */
  return out;
}

/*
 * Table of options whose next argument (or = suffix) is a filesystem path.
 * Keeps resolve_argv_paths() free of hard-coded option names.
 */
static const struct {
  const char *opt;
} path_opts[] = {
    {"--config"}, {"-C"}, {nullptr},
};

void resolve_argv_paths(int argc, char **argv) {
  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];
    if (!arg || arg[0] != '-') /* fast skip: non-option args are not paths */
      continue;

    for (int j = 0; path_opts[j].opt; j++) {
      const char *opt = path_opts[j].opt;
      size_t olen = strlen(opt);

      /* "--opt=VALUE" form */
      if (strncmp(arg, opt, olen) == 0 && arg[olen] == '=') {
        const char *val = arg + olen + 1;
        if (!*val || val[0] == '/')
          break; /* absolute paths don't need resolution */
        auto_free char *resolved = resolve_path_arg(val);
        if (resolved) {
          char *new_arg = malloc(olen + 1 + strlen(resolved) + 1);
          if (new_arg) {
            memcpy(new_arg, opt, olen);
            new_arg[olen] = '=';
            strcpy(new_arg + olen + 1, resolved);
            argv[i] = new_arg; /* argv[i] was a kernel-provided pointer; safe to
                                  replace */
          }
        }
        break;
      }

      /* "--opt VALUE" form (value is the next element) */
      if (strcmp(arg, opt) == 0 && i + 1 < argc) {
        const char *val = argv[i + 1];
        if (!val || !*val ||val[0] == '/')
          continue;
        char *resolved = resolve_path_arg(val);
        if (resolved)
          argv[i + 1] = resolved; /* kernel-provided string; safe to replace */
        break;
      }
    }
  }
}

/* Parse human-readable size: "512M", "1G", "2048" (bytes). Returns -1 on error.
 *
 * Use integer and fractional parts separately to avoid precision loss
 * for large values (e.g. 8192G overflows double's 53-bit mantissa):
 *   - Integer part: strtoll → exact long long arithmetic.
 *   - Fractional part (e.g. "1.5G"): limited double multiplication only for
 *     the sub-unit portion, keeping precision loss < 1 byte.
 */
long long parse_size(const char *str) {
  if (!str || !*str)
    return -1;

  errno = 0;
  char *end;
  /* Parse integer part exactly. */
  long long int_part = strtoll(str, &end, 10);
  if (errno || end == str || int_part < 0)
    return -1;

  /* Optional fractional part (e.g. ".5" in "1.5G"). */
  double frac = 0.0;
  if (*end == '.') {
    char *frac_end;
    frac = strtod(end, &frac_end);
    if (frac_end == end || frac < 0)
      return -1;
    end = frac_end;
  }

  long long factor = 1;
  switch (*end | 0x20) { /* tolower */
  case 'k':
    factor = 1024LL;
    break;
  case 'm':
    factor = 1024LL * 1024;
    break;
  case 'g':
    factor = 1024LL * 1024 * 1024;
    break;
  case 't':
    factor = 1024LL * 1024 * 1024 * 1024;
    break;
  case '\0':
    break;
  default:
    return -1;
  }

  /* Overflow check before multiplication. */
  if (factor > 1 && int_part > (long long)(9223372036854775807LL / factor))
    return -1;

  long long result = int_part * factor;
  if (frac != 0.0)
    result += (long long)(frac * (double)factor);
  return result;
}

void format_size(long long bytes, char *buf, size_t sz) {
  if (bytes <= 0) {
    snprintf(buf, sz, "N/A");
    return;
  }
  static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  int u = 0;
  double d = (double)bytes;
  while (d >= 1024 && u < 4) {
    d /= 1024;
    u++;
  }
  snprintf(buf, sz, "%.2f %s", d, units[u]);
}
