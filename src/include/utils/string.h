#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include "common.h"

fs::path resolve_path_arg(const fs::path &path);
int reject_container_name(std::string_view name);
std::string format_privileged_mask(const int mask);

#endif
