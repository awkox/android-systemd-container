#include "asc.h"

bool is_ramfs(const char *path) {
  struct statfs sfs;
  if (statfs(path, &sfs) < 0)
    return false;
  return sfs.f_type == RAMFS_MAGIC || sfs.f_type == TMPFS_MAGIC;
}

int read_proc_environ(const pid_t pid, const char *key, char *value, const size_t size) {
  if (!key || !value || size == 0 || pid <= 0)
    return -1;

  fs::path path = proc_dir / std::to_string(pid) / "environ";
  auto_fclose FILE *f = fopen(path.c_str(), "re");
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
