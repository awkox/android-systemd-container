#include "asc.h"

int collect_pids(pid_t **pids_out, size_t *count_out) {
  if (!pids_out || !count_out)
    return -1;

  *pids_out = nullptr;
  *count_out = 0;

  auto_closedir DIR *d = opendir("/proc");
  if (!d)
    return -1;

  size_t cap = 256;
  size_t count = 0;

  pid_t *pids = static_cast<pid_t *>(malloc(cap * sizeof(pid_t)));
  if (!pids)
    return -1;

  struct dirent *ent;
  while ((ent = readdir(d)) != nullptr) {

    char *end;
    errno = 0;
    const long val = strtol(ent->d_name, &end, 10);

    if (errno != 0 || *end != '\0' || val <= 0)
      continue;

    if (count >= cap) {
      cap *= 2;
      pid_t *tmp = static_cast<pid_t *>(realloc(pids, cap * sizeof(pid_t)));
      if (!tmp) {
        free(pids);
        return -1;
      }
      pids = tmp;
    }

    pids[count++] = static_cast<pid_t>(val);
  }

  *pids_out = pids;
  *count_out = count;
  return 0;
}

int build_proc_root_path(const pid_t pid, const char *suffix, char *buf,
                         const size_t size) {
  int r;
  if (suffix && suffix[0])
    r = snprintf(buf, size, PROC_ROOT_FMT "%s", pid, suffix);
  else
    r = snprintf(buf, size, PROC_ROOT_FMT, pid);
  return r > 0 && static_cast<size_t>(r) < size ? 0 : -1;
}

bool is_container_init(const pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  auto_fclose FILE *f = fopen(path, "re");
  if (!f)
    return false;

  char line[1024];
  bool is_init = false;
  bool nspid_found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "NSpid:", 6) == 0) {
      nspid_found = true;
      char *p = line + 6;
      const char *last_val = nullptr;
      char *saveptr;
      const char *token = strtok_r(p, " \t\n\r", &saveptr);
      while (token) {
        last_val = token;
        token = strtok_r(nullptr, " \t\n\r", &saveptr);
      }
      if (last_val && strcmp(last_val, "1") == 0) {
        is_init = true;
      }
      break;
    }
  }

  if (nspid_found)
    return is_init;

  struct stat st_pid, st_host;
  char ns_path[PATH_MAX];

  snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/pid", pid);
  if (stat(ns_path, &st_pid) < 0)
    return false;

  if (stat("/proc/1/ns/pid", &st_host) < 0)
    return false;

  return st_pid.st_ino != st_host.st_ino;
}

pid_t find_container_init_pid(const char *uuid) {
  if (!uuid || uuid[0] == '\0')
    return 0;

  char marker[PATH_MAX];
  snprintf(marker, sizeof(marker), FORK_MARKER "/%s", uuid);

  auto_free pid_t *pids = nullptr;
  size_t count = 0;
  char path[PATH_MAX];

  if (collect_pids(&pids, &count) < 0)
    return 0;

  for (size_t i = 0; i < count; i++) {
    if (build_proc_root_path(pids[i], FORK_MARKER, path, sizeof(path)) < 0)
      continue;

    if (access(path, F_OK) == 0) {
      build_proc_root_path(pids[i], marker, path, sizeof(path));
      if (access(path, F_OK) == 0) {
        if (is_valid_container_pid(pids[i])) {
          const pid_t found = pids[i];
          return found;
        }
      }
    }
  }

  return 0;
}