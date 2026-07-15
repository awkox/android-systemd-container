#include "asc.h"

// 动态获取内核当前支持的所有块设备文件系统类型
static std::vector<std::string> get_supported_block_fs() {
    std::vector<std::string> fs_types;
    std::ifstream f("/proc/filesystems");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string token;
        if (iss >> token) {
            if (token == "nodev") {
                continue; // 跳过不支持块设备的虚拟文件系统
            }
            fs_types.push_back(token);
        }
    }
    return fs_types;
}

int mount_rootfs_img(const fs::path& img_path, const fs::path& mount_point) {
    if (!create_directories_with_permission(mount_point)) {
        log_error("创建挂载目录 %s 失败: %s", mount_point.c_str(), strerror(errno));
        return -1;
    }

    sync();
    usleep(RETRY_DELAY_US);
    constexpr unsigned long mnt_flags = MS_NOATIME | MS_NODIRATIME;

    // 1. 获取当前内核支持的文件系统列表
    const auto supported_fs = get_supported_block_fs();

    for (int attempt : std::views::iota(0, 3)) {
        if (attempt == 0)
            log_info("正在尝试挂载镜像 %s 到 %s...", img_path.c_str(), mount_point.c_str());
        else
            log_info("正在重试挂载 (第 %d/3 次尝试)...", attempt + 1);

        fs::path final_src = "";
        int loop_fd = loop_attach(img_path.c_str(), final_src);
        if (loop_fd < 0) return -1;

        bool success = false;

        // 2. 遍历尝试内核支持的所有文件系统
        for (const auto& fstype : supported_fs) {
            if (mount(final_src.c_str(), mount_point.c_str(), fstype.c_str(), mnt_flags, nullptr) == 0) {
                log_info("识别到文件系统并成功挂载 (%s)", fstype.c_str());
                success = true;
                break; // 只要有一个成功，立即退出嗅探循环
            }
        }

        if (!success) {
            log_warn("挂载失败: 当前内核支持的文件系统均无法识别此镜像");
        }

        unlink(final_src.c_str());
        close(loop_fd);

        if (success) return 0;

        if (attempt < 2) {
            sync();
            usleep(RETRY_DELAY_US * 5);
        }
    }
    return -1;
}

int mask_path(const char *path) {
  if (!fs::exists(path))
    return 0;
  if (mount(path, path, nullptr, MS_BIND, nullptr) < 0)
    return -1;
  return mount(path, path, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
}
