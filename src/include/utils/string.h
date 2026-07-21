#ifndef ASC_UTILS_STRING_H
#define ASC_UTILS_STRING_H

#include <string_view>
#include <string>

int reject_container_name(std::string_view name);
std::string format_privileged_mask(const int mask);

#endif
