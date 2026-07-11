#ifndef ASC_UTILS_LOGGER_H
#define ASC_UTILS_LOGGER_H

#include "common.h"

void open_container_log(const std::string& container_name);
void close_container_log();
void write_monitor_debug_log(const std::string& name, const char *fmt, ...);
void print_privileged_warning(const int privileged_mask);

#endif
