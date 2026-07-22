#include <string_view>
#include <sys/types.h>
#include <unistd.h>

#include "core.h"
#include "oci.h"
#include "utils/process.h"

namespace asc::core {

bool is_container_running(std::string_view container_name, pid_t &pid_out) {
  const pid_t deep_pid = find_container_init_pid(container_name);
  if (deep_pid > 0) {
    pid_out = deep_pid;
    return true;
  }

  pid_out = -1;
  return false;
}

void cleanup_container_resources(std::string_view container_name,
                                 const bool force_cleanup) {
  if (!force_cleanup)
    sync();

  asc::oci::cgroup_cleanup_container(container_name);
}

} // namespace asc::core