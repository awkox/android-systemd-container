#ifndef ASC_UTILS_WORKSPACE_H
#define ASC_UTILS_WORKSPACE_H

#include "common.h"

const fs::path get_lock_dir();
const fs::path get_logs_dir();
int ensure_runtime(void);

#endif
