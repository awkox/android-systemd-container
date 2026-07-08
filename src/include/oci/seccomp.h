#ifndef ASC_OCI_SECCOMP_H
#define ASC_OCI_SECCOMP_H

#include "common.h"

int seccomp_apply_minimal(const int privileged_mask);
int android_seccomp_setup(const bool block_nested_ns, const int privileged_mask);

#endif
