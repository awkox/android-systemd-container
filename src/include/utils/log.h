#ifndef ASC_UTILS_LOG_H
#define ASC_UTILS_LOG_H

#include <cstdio>
#include <format>
#include <print>
#include <string_view>
#include <utility>

template <typename... Args>
void log_internal(const char *prefix, bool is_err,
                  std::format_string<Args...> fmt, Args &&...args) {
  FILE *out = is_err ? stderr : stdout;
  std::print(out, "[{}] {}\r\n", prefix,
             std::format(fmt, std::forward<Args>(args)...));
  fflush(out);
}

template <typename... Args>
void log_info(std::format_string<Args...> fmt, Args &&...args) {
  log_internal("+", false, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void log_warn(std::format_string<Args...> fmt, Args &&...args) {
  log_internal("!", true, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void log_error(std::format_string<Args...> fmt, Args &&...args) {
  log_internal("-", true, fmt, std::forward<Args>(args)...);
}

inline void print_privileged_warning(const int privileged_mask) {
  if (privileged_mask <= 0)
    return;
  printf("警告: 特权模式(PRIVILEGED)已激活 - 设备安全性已被降级\r\n\r\n");
  fflush(stdout);
}

#endif