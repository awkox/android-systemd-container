#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include "common.h"

void safe_strncpy(char *dst, const char *src, const size_t size);
fs::path resolve_path_arg(const fs::path& path);
void format_uptime(const long uptime_sec, char *buf, const size_t size);
int reject_container_name(const std::string& name);
std::string format_privileged_mask(const int mask);

#endif
