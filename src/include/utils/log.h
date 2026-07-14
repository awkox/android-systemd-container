#ifndef ASC_UTILS_LOG_H
#define ASC_UTILS_LOG_H

#include "common.h"

[[gnu::format(printf, 3, 4)]]
void log_internal(const char *prefix, bool is_err, const char *fmt, ...);

[[gnu::format(printf, 1, 2)]]
void die_internal(const char *fmt, ...);

#define log_info(fmt, ...) log_internal("+", false, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_warn(fmt, ...) log_internal("!", true, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_error(fmt, ...) log_internal("-", true, fmt __VA_OPT__(,) __VA_ARGS__)
#define log_die(fmt, ...) die_internal(fmt __VA_OPT__(,) __VA_ARGS__)

#endif