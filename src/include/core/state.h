#ifndef ASC_CORE_STATE_H
#define ASC_CORE_STATE_H

#include <string_view>
#include <sys/types.h>

bool is_container_running(std::string_view container_name, pid_t &pid_out);

#endif