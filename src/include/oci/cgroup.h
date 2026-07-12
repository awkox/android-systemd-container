#ifndef ASC_OCI_CGROUP_H
#define ASC_OCI_CGROUP_H

#include "common.h"

bool cgroup_host_is_v2();
int cgroup_host_bootstrap();
void cgroup_cleanup_container(std::string_view container_name);

#endif
