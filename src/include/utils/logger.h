#ifndef ASC_UTILS_LOGGER_H
#define ASC_UTILS_LOGGER_H

#include "common.h"

void open_container_log(std::string_view container_name);
void close_container_log();
void write_monitor_debug_log(std::string_view name, const char *fmt, ...);
void print_privileged_warning(const int privileged_mask);

#endif
