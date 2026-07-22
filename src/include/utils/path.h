#ifndef ASC_UTILS_PATH_H
#define ASC_UTILS_PATH_H

#include <filesystem>

inline const std::filesystem::path tmp_dir = std::filesystem::path("/tmp");
inline const std::filesystem::path proc_dir = std::filesystem::path("/proc");
inline const std::filesystem::path cgroup_dir =
    std::filesystem::path("/sys/fs/cgroup");
inline const std::filesystem::path mount_dir =
    std::filesystem::path("/mnt/asc");
inline const std::filesystem::path project_cgroup_dir = cgroup_dir / "asc";
inline const std::filesystem::path runtime_dir = tmp_dir / "asc";
inline const std::filesystem::path lock_dir = runtime_dir / "lock";

#endif