#ifndef ASC_PLATFORM_CONSOLE_H
#define ASC_PLATFORM_CONSOLE_H

#include <sys/types.h>
#include "common.h"

int console_monitor_loop(int console_master_fd, pid_t monitor_pid, asc::rt &rt);

#endif
