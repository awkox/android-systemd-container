#ifndef ASC_CORE_STATE_H
#define ASC_CORE_STATE_H

#include "common.h"

bool is_container_running(const std::string& container_name, pid_t *pid_out);

#endif