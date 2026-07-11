#ifndef ASC_OCI_CGROUP_H
#define ASC_OCI_CGROUP_H

#include "common.h"

bool cgroup_host_is_v2();
int cgroup_host_bootstrap();
int setup_cgroups();
void cgroup_cleanup_container(const char *container_name);

#endif
