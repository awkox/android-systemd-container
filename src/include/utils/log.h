#ifndef UTILS_LOG_H
#define UTILS_LOG_H

extern bool log_silent;
extern char log_container_name[256];
extern int log_container_fd;

[[gnu::format(printf, 4, 5)]]
void log_internal(const char *prefix, const char *color, bool is_err, const char *fmt, ...);
[[gnu::format(printf, 1, 2)]]
void die_internal(const char *fmt, ...);
void rotate_log(const char *path, size_t max_size);

#define log_info(fmt, ...) log_internal("+", C_GREEN, false, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_warn(fmt, ...) log_internal("!", C_YELLOW, true, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_error(fmt, ...) log_internal("-", C_RED, true, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_die(fmt, ...) die_internal(fmt __VA_OPT__(,) __VA_ARGS__)

#endif // UTILS_LOG_H