#ifndef ASC_PLATFORM_CONSOLE_H
#define ASC_PLATFORM_CONSOLE_H

#include <string_view>
#include <sys/types.h>

int console_monitor_loop(int console_master_fd, pid_t monitor_pid,
                         std::string_view container_name);

#endif
