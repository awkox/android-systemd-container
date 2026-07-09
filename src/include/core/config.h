#ifndef ASC_CORE_CONFIG_H
#define ASC_CORE_CONFIG_H

#include "common.h"

int config_load(fs::path config_path, cfg_t *cfg);
int config_save(fs::path config_path, cfg_t *cfg);
int config_load_by_name(const char *name, cfg_t *cfg);
int config_save_by_name(const char *name, cfg_t *cfg);

#endif
