#ifndef ASC_CORE_CONTAINER_H
#define ASC_CORE_CONTAINER_H

#include "common.h"

bool is_external_lock_active(const char *name);
int acquire_external_lock(const char *name);
void release_external_lock();
void cleanup_container_resources(cfg_t *cfg, const bool force_cleanup);
bool is_valid_container_pid(const pid_t pid);
int start_rootfs(cfg_t *cfg);
int stop_rootfs(cfg_t *cfg);
int show_info(cfg_t *cfg, const bool trust_cfg_pid);

#endif
