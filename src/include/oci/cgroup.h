#ifndef ASC_OCI_CGROUP_H
#define ASC_OCI_CGROUP_H

#include "common.h"

bool cgroup_host_is_v2();
void cgroup_host_bootstrap(const bool force_cgroupv1);
int setup_cgroups(const bool force_cgroupv1);
void cgroup_cleanup_container(const char *container_name);
void print_cgroup_status(const asc_conf_t *conf);
bool cg_word_in_list(const char *list, const char *name);
int cgroup_apply_limits(cfg_t *cfg);
int cgroup_get_usage(const char *container_name, long long *mem, long long *cpu_us, long long *pids);

#endif
