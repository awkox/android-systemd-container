#ifndef ASC_UTILS_PROCESS_H
#define ASC_UTILS_PROCESS_H

#include "common.h"

std::optional<std::vector<pid_t>> collect_pids();
bool is_container_init(const pid_t pid);
pid_t find_container_init_pid(const char *container_name, const char *uuid);
long get_container_uptime(const pid_t pid);

#endif
