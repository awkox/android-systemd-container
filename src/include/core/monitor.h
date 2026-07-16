#ifndef ASC_CORE_MONITOR_H
#define ASC_CORE_MONITOR_H

#include "common.h"

namespace asc::core {

void monitor_run(asc::rt &rt, int sync_pipe_write);

}

#endif
