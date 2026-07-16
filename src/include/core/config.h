#ifndef ASC_CORE_CONFIG_H
#define ASC_CORE_CONFIG_H

#include "common.h"

namespace asc::core {

int config_load(const char *config_path, asc::conf &conf);

}
#endif