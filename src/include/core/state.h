#ifndef ASC_CORE_STATE_H
#define ASC_CORE_STATE_H

#include "common.h"

bool is_container_running(const char *container_name, char *uuid, pid_t *pid_out);
std::vector<std::string> collect_active_uuids(size_t max_uuids = MAX_CONTAINERS);

#endif
