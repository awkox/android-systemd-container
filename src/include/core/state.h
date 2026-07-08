#ifndef ASC_CORE_STATE_H
#define ASC_CORE_STATE_H

#include "common.h"

bool is_container_running(char *uuid, pid_t *pid_out);
int collect_active_uuids(char uuids[][UUID_LEN + 1], const int max_uuids);

#endif
