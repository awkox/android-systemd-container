#ifndef ASC_UTILS_PROCESS_H
#define ASC_UTILS_PROCESS_H

#include "common.h"

int collect_pids(pid_t **pids_out, size_t *count_out);
int build_proc_root_path(const pid_t pid, const char *suffix, char *buf, const size_t size);
bool is_container_init(const pid_t pid);
pid_t find_container_init_pid(const char *uuid);
long get_container_uptime(const pid_t pid);

#endif
