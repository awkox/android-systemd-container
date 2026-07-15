#ifndef ASC_CORE_CONTAINER_H
#define ASC_CORE_CONTAINER_H

#include "common.h"

bool is_external_lock_active(std::string_view name);
int acquire_external_lock(std::string_view name);
void release_external_lock();
void cleanup_container_resources(std::string_view container_name, const bool force_cleanup);
bool is_valid_container_pid(const pid_t pid);
int start_rootfs(cfg_t &cfg);
int stop_rootfs(std::string_view container_name);

#endif
