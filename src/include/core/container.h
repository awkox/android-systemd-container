#ifndef ASC_CORE_CONTAINER_H
#define ASC_CORE_CONTAINER_H

#include <string_view>
#include "common.h"

int start_rootfs(asc::rt &rt);
int stop_rootfs(std::string_view container_name);

#endif