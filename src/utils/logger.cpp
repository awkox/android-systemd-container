#include <cstdio>
#include <cstdarg>
#include "utils/logger.h"

[[gnu::format(printf, 3, 4)]]
void log_internal(const char *prefix, const bool is_err, const char *fmt, ...) {
  char raw_msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
  va_end(ap);

  FILE *out = is_err ? stderr : stdout;
  fprintf(out, "[%s] %s\r\n", prefix, raw_msg);
  fflush(out);
}

void print_privileged_warning(const int privileged_mask) {
  if (privileged_mask <= 0)
    return;

  printf("警告: 特权模式(PRIVILEGED)已激活 - 设备安全性已被降级\r\n\r\n");
  fflush(stdout);
}
