#ifndef ASC_CORE_H
#define ASC_CORE_H

#include <string_view>
#include <sys/types.h>
#include "common.h"

namespace asc::core {

int check_requirements_hw();

int config_load(const char *config_path, asc::conf &conf);

int start_rootfs(asc::rt &rt);
int stop_rootfs(std::string_view container_name);

void internal_boot(asc::rt &rt);

bool is_external_lock_active(std::string_view name);
int acquire_external_lock(std::string_view name);
void release_external_lock();
void close_external_lock_fd();

void monitor_run(asc::rt &rt, int sync_pipe_write);

bool is_container_running(std::string_view container_name, pid_t &pid_out);
void cleanup_container_resources(std::string_view container_name, const bool force_cleanup);

}

#endif