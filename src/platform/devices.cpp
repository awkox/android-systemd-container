#include "asc.h"

static int create_devices(const char *rootfs);
static void mirror_gpu_nodes(const char *dev_path);

int setup_dev(const char *rootfs, const bool gpu_mode) {
  char dev_path[PATH_MAX];
  snprintf(dev_path, sizeof(dev_path), "%s/dev", rootfs);

  mkdir(dev_path, 0755);

  if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
              "size=8M,mode=755") < 0)
    return -1;

  if (gpu_mode) {
    log_info("[GPU] GPU 加速模式：正在将宿主机的安全 GPU 节点映射入虚拟 tmpfs");
    mirror_gpu_nodes(dev_path);
  }

  return create_devices(rootfs);
}

static int create_devices(const char *rootfs) {
  const struct {
    const char *name;
    mode_t mode;
    dev_t dev;
  } devices[] = {
    {"null", S_IFCHR | 0666, makedev(1, 3)},
    {"zero", S_IFCHR | 0666, makedev(1, 5)},
    {"full", S_IFCHR | 0666, makedev(1, 7)},
    {"random", S_IFCHR | 0666, makedev(1, 8)},
    {"urandom", S_IFCHR | 0666, makedev(1, 9)},
    {"tty", S_IFCHR | 0666, makedev(5, 0)},
    {"console", S_IFCHR | 0620, makedev(5, 1)},
    {"ptmx", S_IFCHR | 0666, makedev(5, 2)},
    {nullptr, 0, 0}
  };

  char path[PATH_MAX];

  for (int i = 0; devices[i].name; i++) {
    snprintf(path, sizeof(path), "%s/dev/%s", rootfs, devices[i].name);

    force_unlink(path);

    if (mknod(path, devices[i].mode, devices[i].dev) < 0) {
      char host_path[PATH_MAX];
      snprintf(host_path, sizeof(host_path), "/dev/%s", devices[i].name);
      bind_mount(host_path, path);
    } else {
      chmod(path, devices[i].mode & 0777);
      if (strcmp(devices[i].name, "console") == 0 ||
          strcmp(devices[i].name, "tty") == 0) {
        if (chown(path, 0, 5) < 0) {}
      }
    }
  }

  snprintf(path, sizeof(path), "%s/dev/net", rootfs);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/dev/net/tun", rootfs);
  force_unlink(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 200)) < 0)
    bind_mount("/dev/net/tun", path);
  else
    chmod(path, 0666);

  snprintf(path, sizeof(path), "%s/dev/fuse", rootfs);
  force_unlink(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 229)) < 0)
    bind_mount("/dev/fuse", path);
  else
    chmod(path, 0666);

  char tgt[PATH_MAX];
  snprintf(tgt, sizeof(tgt), "%s/dev/fd", rootfs);
  if (symlink("/proc/self/fd", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/fd 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdin", rootfs);
  if (symlink("/proc/self/fd/0", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stdin 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdout", rootfs);
  if (symlink("/proc/self/fd/1", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stdout 符号链接失败: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stderr", rootfs);
  if (symlink("/proc/self/fd/2", tgt) < 0 && errno != EEXIST)
    log_warn("建立 /dev/stderr 符号链接失败: %s", strerror(errno));

  return 0;
}

int setup_devpts() {
  const char *pts_path = "/dev/pts";

  umount2(pts_path, MNT_DETACH);
  mkdir(pts_path, 0755);

  char optbuf[256];
  snprintf(optbuf, sizeof(optbuf), "gid=%d,newinstance,ptmxmode=0666,mode=0620",
           DEFAULT_TTY_GID);

  char optbuf2[128];
  snprintf(optbuf2, sizeof(optbuf2), "gid=%d,newinstance,mode=0620",
           DEFAULT_TTY_GID);

  const char *opts[] = {
    optbuf,
    "newinstance,ptmxmode=0666,mode=0620",
    optbuf2,
    "newinstance,ptmxmode=0666",
    "newinstance",
    nullptr
  };

  for (int i = 0; opts[i]; i++) {
    if (domount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, opts[i]) == 0) {
      const char *ptmx_path = "/dev/ptmx";
      const char *pts_ptmx = "/dev/pts/ptmx";

      unlink(ptmx_path);

      if (write_file(ptmx_path, "") == 0) {
        if (mount(pts_ptmx, ptmx_path, nullptr, MS_BIND, nullptr) == 0) {
          return 0;
        }
      }

      unlink(ptmx_path);
      if (symlink("pts/ptmx", ptmx_path) == 0 && access(pts_ptmx, F_OK) == 0)
        return 0;

      unlink(ptmx_path);
      if (mknod(ptmx_path, S_IFCHR | 0666, makedev(5, 2)) == 0) {
        chmod(ptmx_path, 0666);
        return 0;
      }

      log_warn("无法虚拟化 /dev/ptmx，部分伪终端应用可能会失败");
      return 0;
    }
  }

  log_error("挂载 devpts (newinstance) 失败");
  return -1;
}

int fix_host_ptys(void) {
  const char *pts_path = "/dev/pts";

  if (is_mountpoint(pts_path))
    return 0;

  mkdir(pts_path, 0755);

  if (mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC,
            "gid=5,mode=620") < 0) {
    if (errno != EBUSY) {
      log_warn("恢复宿主机 devpts 失败: %s", strerror(errno));
      return -1;
    }
  }

  log_info("宿主机 devpts 已成功恢复挂载 (Recovery 环境修复)。");
  return 0;
}

static const struct {
  const char *dir;
  const char *prefix;
} gpu_scan_dirs[] = {
  {"/dev/dri", "renderD"},
  {"/dev", "nvidia"},
  {"/dev", "video"},
  {"/dev/nvidia-caps", nullptr},
  {"/dev", "mali"},
  {"/dev", "kgsl"},
  {"/dev/dma_heap", nullptr},
  {nullptr, nullptr}, 
};

static const char *gpu_static_devices[] = {
  "/dev/binder", "/dev/vndbinder", "/dev/hwbinder",
  "/dev/ion", "/dev/ashmem",
  "/dev/mali", "/dev/genlock",
  "/dev/kfd",
  "/dev/pvrsrvkm", "/dev/pvr_sync",
  "/dev/nvhost-ctrl", "/dev/nvhost-gpu", "/dev/nvhost-ctrl-gpu",
  "/dev/nvhost-as-gpu", "/dev/nvhost-dbg-gpu", "/dev/nvhost-prof-gpu",
  "/dev/nvhost-tsg", "/dev/nvhost-tsg-gpu", "/dev/nvhost-vic",
  "/dev/nvhost-nvdec", "/dev/nvhost-nvdec1", "/dev/nvhost-nvenc",
  "/dev/nvhost-msenc", "/dev/nvmap",
  "/dev/dxg",
  "/dev/sw_sync",
  nullptr,
};

static bool is_dangerous_node(const char *name) {
  if (!name || name[0] == '\0') 
    return false;

  std::string_view sv{name};
  const size_t len = sv.length();

  // 1. 特殊逻辑判断 (高频 & 包含放行逻辑的规则)
  // 提前执行，快速放行安全节点或处理带通配数字的设备
  if (sv.starts_with("tty")) {
    // 白名单放行特定的串口通信节点
    if (sv.starts_with("ttyUSB") || sv.starts_with("ttyACM") ||
        sv.starts_with("ttyAMA") || sv.starts_with("ttyTHS") ||
        sv.starts_with("ttymxc")) {
      return false;
    }
    if (len > 3 && std::isdigit(name[3])) return true;
    if (sv.starts_with("ttyBCM")) return true;
  }

  // 处理前缀 + 可选/必填数字的逻辑
  if (sv.starts_with("card") && (len == 4 || std::isdigit(name[4]))) return true;
  if (sv.starts_with("controlD") && (len == 8 || std::isdigit(name[8]))) return true;
  if (sv.starts_with("nvidia") && len > 6 && std::isdigit(name[6])) return true;
  if (sv.starts_with("fb") && len > 2 && std::isdigit(name[2])) return true;
  if (sv.starts_with("ram") && len > 3 && std::isdigit(name[3])) return true;
  if (sv.starts_with("aed") && (len == 3 || std::isdigit(name[3]))) return true;

  // 唯一需要忽略大小写的匹配项
  if (len >= 7 && strncasecmp(name, "mt_pmic", 7) == 0) return true;


  // 2. O(log N) 二分查找精确匹配 (Exact Matches)
  // 将所有的 strcmp == 0 提取并按字典序(ASCII)排序，使用二分查找瞬间出结果
  static constexpr std::string_view exact_matches[] = {
      "RT_Monitor", "android_ssusbcon", "audio_ipi", "ccic_misc", "console",
      "cvp", "dcc_sram", "drm_wv", "eara-io", "fimg2d", "fmp", "fmt_sync",
      "full", "g2d", "goodix_fp", "gps_emi", "gps_pwr", "hqm_event", "initctl",
      "k250a", "kmem", "kmsg", "mcupm", "mddp", "mdp_sync", "mem",
      "memory_bandwidth", "met", "mml_pq", "mmp", "mst_ctrl", "mtk_mdp",
      "mtk_sec", "null", "nvidia-modeset", "nvidiactl", "port", "ptmx",
      "radio0", "random", "rfkill", "s5p-smem", "sa_log_wifi", "scp",
      "scp_audio_ipi", "sec-nfc", "sec_display_debug", "self_display",
      "snapshot", "spec_sync", "ssp_sensorhub", "sspm", "stats", "synx_device",
      "tty", "tuihw", "udmabuf", "uinput", "urandom", "usip", "vcp",
      "vertex10", "vga_arbiter", "vow", "wlan", "zero"
  };
  if (std::binary_search(std::begin(exact_matches), std::end(exact_matches), sv)) {
    return true;
  }


  // 3. 线性前缀匹配 (Prefix Matches)
  // 将所有的 starts_with 归拢在一起统一遍历
  static constexpr std::string_view prefixes[] = {
      "als_", "anbox-", "apr_", "at_mdm", "at_usb", "bbd_", "btfmslim",
      "btpower", "ccci", "cluster", "conn", "coresight", "cpu_online_",
      "dek_", "drm_dp_aux", "fw_log_", "gh_", "gpiochip", "gpu_freq",
      "gz_", "hvc", "i2c-", "iio:device", "ipa", "modem_boot", "nr_",
      "nvidia-cap", "pmsg", "pty", "qbt", "rdbg_", "remoteproc", "rmnet_",
      "rpmb", "rpmsg_", "sipa_", "smd", "ssp_", "stp", "tee", "tpm",
      "trusty", "tz", "umts_", "vcs", "wmt", "wwan_"
  };
  for (const auto& prefix : prefixes) {
    if (sv.starts_with(prefix)) return true;
  }


  // 4. 最重负载的子串匹配 (Substring Matches) 
  // 将所有 strstr 放到最后兜底，避免非必要的高消耗查找
  static constexpr std::string_view substrings[] = {
      "adsprpc", "aud_", "icnss_", "latency", "msm_audio_ion", "msm_hdcp",
      "msm_sps", "multipdp", "qseecom", "smcinvoke", "throughput", "watchdog"
  };
  for (const auto& sub : substrings) {
    if (sv.find(sub) != std::string_view::npos) return true;
  }

  return false;
}

static void mirror_gpu_node(const char *host_path, const char *dev_path) {
  if (strncmp(host_path, "/dev/", 5) != 0)
    return;

  const char *node_name = strrchr(host_path, '/');
  node_name = node_name ? node_name + 1 : host_path;
  if (is_dangerous_node(node_name))
    return;

  struct stat host_st;
  if (stat(host_path, &host_st) < 0)
    return;
  if (!S_ISCHR(host_st.st_mode))
    return;

  const char *rel = host_path + 5; 
  char tgt[PATH_MAX];
  snprintf(tgt, sizeof(tgt), "%s/%s", dev_path, rel);

  char parent[PATH_MAX];
  snprintf(parent, sizeof(parent), "%s", tgt);
  char *slash = strrchr(parent, '/');
  if (slash && slash != parent) {
    *slash = '\0';
    mkdir(parent, 0755); 
  }

  struct stat tgt_st;
  if (lstat(tgt, &tgt_st) == 0) {
    if (S_ISCHR(tgt_st.st_mode)) {
      if (chown(tgt, 0, 0) < 0)
        log_warn("[GPU] 重新授权已有节点 %s → root:root: %s", tgt,
                 strerror(errno));
      chmod(tgt, 0666);
      return;
    }

    if (S_ISDIR(tgt_st.st_mode)) {
      if (rmdir(tgt) < 0) {
        log_warn("[GPU] 无法清理冲突的目录 %s: %s", tgt,
                 strerror(errno));
        return;
      }
    } else {
      unlink(tgt);
    }
  }

  const mode_t mode = S_IFCHR | (host_st.st_mode & 0666);
  if (mknod(tgt, mode, host_st.st_rdev) < 0) {
    log_warn("[GPU] mknod 创建节点 %s (%d:%d) 失败: %s", tgt,
             (int)major(host_st.st_rdev), (int)minor(host_st.st_rdev),
             strerror(errno));
    return;
  }

  if (chown(tgt, 0, 0) < 0)
    log_warn("[GPU] 授权节点 %s → root:root: %s", tgt, strerror(errno));
  chmod(tgt, 0666);

  log_info("[GPU] 已成功镜像节点: %-30s (%d:%d)", tgt,
           (int)major(host_st.st_rdev), (int)minor(host_st.st_rdev));
}

static void do_mirror_gpu_dir(const char *host_dir, const char *prefix,
                              const char *dev_path) {
  auto_closedir DIR *dir = opendir(host_dir);
  if (!dir)
    return;

  struct dirent *entry;
  char full_path[PATH_MAX];

  while ((entry = readdir(dir)) != nullptr) {
    if (entry->d_name[0] == '.')
      continue;
    if (prefix && strncmp(entry->d_name, prefix, strlen(prefix)) != 0)
      continue;

    snprintf(full_path, sizeof(full_path), "%s/%s", host_dir, entry->d_name);
    mirror_gpu_node(full_path, dev_path);
  }
}

static void mirror_gpu_nodes(const char *dev_path) {
  for (int i = 0; gpu_scan_dirs[i].dir != nullptr; i++)
    do_mirror_gpu_dir(gpu_scan_dirs[i].dir, gpu_scan_dirs[i].prefix, dev_path);

  for (int i = 0; gpu_static_devices[i] != nullptr; i++)
    mirror_gpu_node(gpu_static_devices[i], dev_path);
}