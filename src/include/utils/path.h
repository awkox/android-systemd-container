#ifndef ASC_UTILS_PATH_H
#define ASC_UTILS_PATH_H

#include "common.h"

inline const fs::path tmp_dir      = fs::path("/tmp");
inline const fs::path proc_dir     = fs::path("/proc");
inline const fs::path cgroup_dir   = fs::path("/sys/fs/cgroup");
inline const fs::path mount_dir    = fs::path("/mnt/asc");
inline const fs::path project_cgroup_dir = cgroup_dir / "asc";
inline const fs::path runtime_dir  = tmp_dir / "asc";
inline const fs::path config_dir   = runtime_dir / "config";
inline const fs::path lock_dir     = runtime_dir / "lock";

#endif