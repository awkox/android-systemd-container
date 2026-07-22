#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include <string>
#include <string_view>

int reject_container_name(std::string_view name);
std::string format_privileged_mask(const int mask);

#endif
