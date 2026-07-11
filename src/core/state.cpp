#include "asc.h"

bool is_container_running(const std::string& container_name, pid_t *pid_out) {
  const pid_t deep_pid = find_container_init_pid(container_name);
  if (deep_pid > 0) {
    if (pid_out)
      *pid_out = deep_pid;
    return true;
  }

  return false;
}