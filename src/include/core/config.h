#ifndef ASC_CORE_CONFIG_H
#define ASC_CORE_CONFIG_H

#include "common.h"

int config_load(const char *config_path, cfg_t *cfg);
int config_save(const char *config_path, cfg_t *cfg);
char *config_auto_path(const char *rootfs_path);
int config_load_by_name(const char *name, cfg_t *cfg);
int config_save_by_name(const char *name, cfg_t *cfg);

#endif
