#include "asc.h"

#define FW_PATH_BUF_SIZE 256

static int fw_remove_token(const char *buf, const char *token, char *out,
                           const size_t out_size) {
  const size_t token_len = strlen(token);
  const char *p = buf;
  bool first = true;
  out[0] = '\0';

  while (*p) {
    const char *comma = strchr(p, ',');
    const size_t seg_len = comma ? static_cast<size_t>(comma - p) : strlen(p);

    if (!(seg_len == token_len && memcmp(p, token, token_len) == 0)) {
      if (!first)
        strncat(out, ",", out_size - strlen(out) - 1);
      strncat(out, p,
              seg_len < out_size - strlen(out) - 1
                  ? seg_len
                  : out_size - strlen(out) - 1);
      first = false;
    }

    if (!comma)
      break;
    p = comma + 1;
  }

  return static_cast<int>(strlen(out));
}

void firmware_path_add(const char *fw_path) {
  struct stat st;
  if (stat(fw_path, &st) < 0)
    return;

  char current[FW_PATH_BUF_SIZE] = "";
  read_file(FW_PATH_FILE, current, sizeof(current));

  const size_t fw_len = strlen(fw_path);
  const char *p = current;
  while (*p) {
    const char *comma = strchr(p, ',');
    const size_t seg_len = comma ? static_cast<size_t>(comma - p) : strlen(p);
    if (seg_len == fw_len && memcmp(p, fw_path, fw_len) == 0)
      return;
    if (!comma)
      break;
    p = comma + 1;
  }

  char new_path[FW_PATH_BUF_SIZE] = "";
  if (current[0]) {
    const size_t needed =
        strlen(fw_path) + 1 + strlen(current) + 1;
    if (needed > sizeof(new_path)) {
      log_warn("[FW] 固件路径太长，无法插入新路径 '%s' - 跳过",
               fw_path);
      return;
    }
    safe_strncpy(new_path, fw_path, sizeof(new_path));
    strncat(new_path, ",", sizeof(new_path) - strlen(new_path) - 1);
    strncat(new_path, current, sizeof(new_path) - strlen(new_path) - 1);
  } else {
    safe_strncpy(new_path, fw_path, sizeof(new_path));
  }

  log_info("[FW] 注入内核固件搜索路径: %s", fw_path);
  write_file(FW_PATH_FILE, new_path);
}

void firmware_path_remove(const char *fw_path) {
  char current[FW_PATH_BUF_SIZE] = "";
  if (read_file(FW_PATH_FILE, current, sizeof(current)) < 0)
    return;

  char new_path[FW_PATH_BUF_SIZE] = "";
  const int new_len = fw_remove_token(current, fw_path, new_path, sizeof(new_path));

  if (new_len == 0) {
    log_info("[FW] 固件路径为系统唯一记录，跳过清理: %s", fw_path);
    return;
  }

  log_info("[FW] 移除内核固件搜索路径: %s", fw_path);
  write_file(FW_PATH_FILE, new_path);
}
