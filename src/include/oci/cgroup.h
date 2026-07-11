#ifndef ASC_OCI_CGROUP_H
#define ASC_OCI_CGROUP_H

#include "common.h"

bool cgroup_host_is_v2();
int cgroup_host_bootstrap();
int setup_cgroups();
void cgroup_cleanup_container(const char *container_name);
bool cg_word_in_list(const char *list, const char *name);
int cgroup_get_usage(const char *container_name, long long *mem, long long *cpu_us, long long *pids);

#endif
