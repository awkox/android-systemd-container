#include "asc.h"

bool is_ramfs(const char *path) {
  struct statfs sfs;
  if (statfs(path, &sfs) < 0)
    return false;
  return sfs.f_type == RAMFS_MAGIC || sfs.f_type == TMPFS_MAGIC;
}

int parse_os_release(const char *rootfs_path, char *id_out, char *ver_out,
                     const size_t out_size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%.4000s" OS_RELEASE, rootfs_path);

  char buf[4096];
  if (read_file(path, buf, sizeof(buf)) < 0)
    return -1;

  safe_strncpy(id_out, "linux", out_size);
  if (ver_out)
    ver_out[0] = '\0';

  char *p = strstr(buf, "\nID=");
  if (!p && strncmp(buf, "ID=", 3) == 0)
    p = buf;

  if (p) {
    if (*p == '\n')
      p++;
    p += 3;
    if (*p == '"')
      p++;
    int i = 0;
    while (p[i] && p[i] != '"' && p[i] != '\n' && static_cast<size_t>(i) < out_size - 1) {
      id_out[i] = p[i];
      i++;
    }
    id_out[i] = '\0';
  }

  if (ver_out) {
    p = strstr(buf, "VERSION_ID=");
    if (p) {
      p += 11;
      if (*p == '"')
        p++;
      int i = 0;
      while (p[i] && p[i] != '"' && p[i] != '\n' && static_cast<size_t>(i) < out_size - 1) {
        ver_out[i] = p[i];
        i++;
      }
      ver_out[i] = '\0';
    }
  }

  return 0;
}

int read_proc_environ(const pid_t pid, const char *key, char *value, const size_t size) {
  if (!key || !value || size == 0 || pid <= 0)
    return -1;

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/environ", pid);

  auto_fclose FILE *f = fopen(path, "re");
  if (!f)
    return -1;

  const int keylen = strlen(key);
  int found = -1;

  while (1) {
    int c = fgetc(f);
    if (c == EOF)
      break;

    if (c == key[0]) {
      const long pos = ftell(f);
      if (pos < 0)
        break;
      fseek(f, pos - 1, SEEK_SET);

      bool matched = true;
      for (int i = 0; i < keylen; i++) {
        const int kc = fgetc(f);
        if (kc != static_cast<unsigned char>(key[i])) {
          matched = false;
          break;
        }
      }
      if (matched && fgetc(f) == '=') {
        int vi = 0;
        while (vi < static_cast<int>(size) - 1) {
          const int vc = fgetc(f);
          if (vc == EOF || vc == '\0')
            break;
          value[vi++] = static_cast<char>(vc);
        }
        value[vi] = '\0';
        found = 0;
        break;
      }
    }

    while ((c = fgetc(f)) != EOF && c != '\0')
      ;
  }

  return found;
}

static int internal_run(char *const argv[], const bool quiet) {
  const pid_t pid = fork();
  if (pid < 0)
    return -1;

  if (pid == 0) {
    if (quiet) {
      auto_close const int devnull = open("/dev/null", O_RDWR);
      if (devnull >= 0) {
        dup2(devnull, 1);
        dup2(devnull, 2);
      }
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  int status;
  if (waitpid(pid, &status, 0) < 0)
    return -1;

  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  return -1;
}

int run_command_quiet(char *const argv[]) {
  return internal_run(argv, true);
}

int get_kernel_version(int *major, int *minor) {
  struct utsname uts;
  if (uname(&uts) < 0)
    return -1;

  if (sscanf(uts.release, "%d.%d", major, minor) != 2)
    return -1;

  return 0;
}

void oom_protect(void) {
  auto_fclose FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f)
    fprintf(f, "-1000\n");
}
