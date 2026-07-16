#ifndef ASC_OCI_H
#define ASC_OCI_H

#include <string_view>

namespace asc::oci {

void apply_capability_hardening(const int privileged_mask);

bool cgroup_host_is_v2();
int cgroup_host_bootstrap();
void cgroup_cleanup_container(std::string_view container_name);

int seccomp_apply_minimal(const int privileged_mask);
int android_seccomp_setup(const bool block_nested_ns, const int privileged_mask);

}

#endif
