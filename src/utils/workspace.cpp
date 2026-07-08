#include "asc.h"

const char *get_runtime_dir(void) {
  return RUNTIME_DIR;
}

const char *get_lock_dir(void) {
  static char lock_path[PATH_MAX];
  snprintf(lock_path, sizeof(lock_path), "%s/%s", get_runtime_dir(),
           RUNTIME_LOCK_SUBDIR);
  return lock_path;
}

const char *get_logs_dir(void) {
  static char logs_path[PATH_MAX];
  snprintf(logs_path, sizeof(logs_path), "%s/%s", get_runtime_dir(),
           RUNTIME_LOGS_SUBDIR);
  return logs_path;
}

int ensure_runtime(void) {
  mkdir_p(get_runtime_dir(), 0755);
  mkdir_p(get_lock_dir(), 0755);
  mkdir_p(get_logs_dir(), 0755);

  return 0;
}

int count_folders(const char *path) {
  auto_closedir DIR *dir = opendir(path);
  struct dirent *entry;
  struct stat st;
  char fullpath[PATH_MAX];
  int count = 0;

  if (!dir)
    return 0;

  const size_t base_len = strlen(path);

  while ((entry = readdir(dir)) != nullptr) {

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    if (base_len + 1 + strlen(entry->d_name) >= sizeof(fullpath))
      continue;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

    if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode))
      count++;
  }

  return count;
}

void generate_container_name(const char *rootfs_path, char *name, const size_t size) {
  char id[64], version[64];

  if (parse_os_release(rootfs_path, id, version, sizeof(id)) < 0) {
    safe_strncpy(name, "linux-container", size);
    return;
  }

  if (version[0])
    snprintf(name, size, "%s-%s", id, version);
  else
    safe_strncpy(name, id, size);
}