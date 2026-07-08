#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include "common.h"

void safe_strncpy(char *dst, const char *src, const size_t size);
void sanitize_container_name(const char *name, char *out, const size_t size);
char *resolve_path_arg(const char *path);
void resolve_argv_paths(const int argc, char **argv);
void format_size(const long long bytes, char *buf, const size_t sz);
void format_uptime(const long uptime_sec, char *buf, const size_t size);
int validate_container_name(const char *name);
int reject_container_name(const char *name);
void format_privileged_mask(const int mask, char *buf, const size_t size);

#endif
