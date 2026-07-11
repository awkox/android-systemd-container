#ifndef ASC_UTILS_PROCESS_H
#define ASC_UTILS_PROCESS_H

#include "common.h"

bool is_container_init(const pid_t pid);
pid_t find_container_init_pid(const std::string& container_name);
long get_container_uptime(const pid_t pid);
unsigned long get_pid_ns_inode(const pid_t pid);

#endif