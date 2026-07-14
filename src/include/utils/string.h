#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include "common.h"

fs::path resolve_path_arg(const fs::path& path);
std::string format_uptime(const long uptime_sec);
int reject_container_name(const std::string& name);
std::string format_privileged_mask(const int mask);

#endif
