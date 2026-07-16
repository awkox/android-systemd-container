#ifndef ASC_CORE_LOCK_H
#define ASC_CORE_LOCK_H

#include <string_view>

bool is_external_lock_active(std::string_view name);
int acquire_external_lock(std::string_view name);
void release_external_lock();
void close_external_lock_fd();

#endif
