#include "asc.h"

static int create_devices(const char *rootfs);
static bool is_dangerous_node(const char *name);
static void mirror_gpu_nodes(const char *dev_path);

static void prune_host_devices(const char *dev_path, const int privileged_mask) {
  if (privileged_mask & PRIV_UNFILT) {
    log_info("[SEC] 已激活 --privileged=unfiltered-dev: 跳过设备节点黑名单过滤。");
    return;
  }
  auto_closedir DIR *dir = opendir(dev_path);
  if (!dir)
    return;

  struct dirent *entry;
  char path[PATH_MAX];

  while ((entry = readdir(dir)) != nullptr) {
    const char *name = entry->d_name;
    bool should_unlink = false;

    if (is_dangerous_node(name)) {
      should_unlink = true;
    }

    if (should_unlink) {
      snprintf(path, sizeof(path), "%.3800s/%s", dev_path, name);
      umount2(path, MNT_DETACH);
      force_unlink(path);
      continue;
    }

    if (strcmp(name, "dri") == 0 || strcmp(name, "nvidia-caps") == 0) {
      snprintf(path, sizeof(path), "%.3800s/%s", dev_path, name);
      auto_closedir DIR *subdir = opendir(path);
      if (subdir) {
        struct dirent *subentry;
        while ((subentry = readdir(subdir)) != nullptr) {
          bool sub_unlink = false;
          const char *subname = subentry->d_name;

          if (is_dangerous_node(subname)) {
            sub_unlink = true;
          }

          if (sub_unlink) {
            char subpath[PATH_MAX];
            snprintf(subpath, sizeof(subpath), "%.3800s/%s", path, subname);
            unlink(subpath);
          }
        }

        if (strcmp(name, "dri") == 0) {
          char bp_path[PATH_MAX];
          snprintf(bp_path, sizeof(bp_path), "%.3800s/by-path", path);
          auto_closedir DIR *bp_dir = opendir(bp_path);
          if (bp_dir) {
            while ((subentry = readdir(bp_dir)) != nullptr) {
              if (strstr(subentry->d_name, "-card")) {
                char bppath[PATH_MAX];
                snprintf(bppath, sizeof(bppath), "%.3800s/%s", bp_path,
                         subentry->d_name);
                unlink(bppath);
              }
            }
          }
        }
      }
    }
  }
}

int setup_dev(const char *rootfs, const bool hw_access, const bool gpu_mode,
              const int privileged_mask) {
  char dev_path[PATH_MAX];
  snprintf(dev_path, sizeof(dev_path), "%s/dev", rootfs);

  mkdir(dev_path, 0755);

  if (hw_access) {
    if (domount("devtmpfs", dev_path, "devtmpfs", MS_NOSUID | MS_NOEXEC,
                "mode=755") == 0) {
      prune_host_devices(dev_path, privileged_mask);
      mirror_gpu_nodes(dev_path);
    } else {
      log_warn("挂载 devtmpfs 失败，回退使用受限的 tmpfs 伪终端");
      if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
                  "size=8M,mode=755") < 0)
        return -1;
    }
  } else {
    if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
                "size=8M,mode=755") < 0)
      return -1;

    if (gpu_mode) {
      log_info(
          "[GPU] --gpu 加速模式：正在将宿主机的安全 GPU 节点映射入虚拟 tmpfs");
      mirror_gpu_nodes(dev_path);
    }
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

int setup_devpts(const bool hw_access) {
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

      if (hw_access) {
        if (mount(pts_ptmx, ptmx_path, nullptr, MS_BIND, nullptr) == 0) {
          return 0;
        }
      } else {
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
  if ((strncmp(name, "card", 4) == 0 &&
       (name[4] == '\0' || isdigit(name[4]))) ||
      (strncmp(name, "controlD", 8) == 0 &&
       (name[8] == '\0' || isdigit(name[8])))) {
    return true;
  }

  if (strcmp(name, "nvidiactl") == 0 || strcmp(name, "nvidia-modeset") == 0)
    return true;
  if (strncmp(name, "nvidia", 6) == 0 && isdigit(name[6]))
    return true;
  if (strncmp(name, "nvidia-cap", 10) == 0)
    return true;

  if (strcmp(name, "vga_arbiter") == 0)
    return true;
  if (strncmp(name, "fb", 2) == 0 && isdigit(name[2]))
    return true;

  if (strncmp(name, "tty", 3) == 0) {
    if (strncmp(name, "ttyUSB", 6) == 0 || strncmp(name, "ttyACM", 6) == 0 ||
        strncmp(name, "ttyAMA", 6) == 0 || strncmp(name, "ttyTHS", 6) == 0 ||
        strncmp(name, "ttymxc", 6) == 0)
      return false;
    if (isdigit(name[3]))
      return true;
    return true;
  }

  if (strncmp(name, "ccci", 4) == 0 || strncmp(name, "umts_", 5) == 0)
    return true;
  if (strncmp(name, "pty", 3) == 0) 
    return true;
  if (strcmp(name, "uinput") == 0 || strcmp(name, "rfkill") == 0)
    return true;
  if (strncmp(name, "tz", 2) == 0 || strncmp(name, "trusty", 6) == 0 ||
      strncmp(name, "gz_", 3) == 0 || strncmp(name, "tee", 3) == 0)
    return true; 
  if (strncmp(name, "conn", 4) == 0 || strcmp(name, "mtk_sec") == 0)
    return true; 
  if (strncasecmp(name, "mt_pmic", 7) == 0)
    return true; 
  if (strcmp(name, "tuihw") == 0 || strcmp(name, "wlan") == 0)
    return true;
  if (strncmp(name, "ram", 3) == 0 && isdigit(name[3]))
    return true; 

  if (strcmp(name, "console") == 0 || strcmp(name, "tty") == 0 ||
      strcmp(name, "full") == 0 || strcmp(name, "null") == 0 ||
      strcmp(name, "zero") == 0 || strcmp(name, "random") == 0 ||
      strcmp(name, "urandom") == 0 || strcmp(name, "ptmx") == 0 ||
      strcmp(name, "initctl") == 0)
    return true;

  if (strcmp(name, "mem") == 0 || strcmp(name, "kmem") == 0 ||
      strcmp(name, "port") == 0 || strcmp(name, "kmsg") == 0)
    return true;
  if (strncmp(name, "drm_dp_aux", 10) == 0)
    return true;
  if (strncmp(name, "vcs", 3) == 0)
    return true;
  if (strstr(name, "watchdog") != nullptr)
    return true;

  if (strstr(name, "qseecom") != nullptr || strstr(name, "smcinvoke") != nullptr ||
      strstr(name, "adsprpc") != nullptr)
    return true;

  if (strcmp(name, "udmabuf") == 0 || strcmp(name, "snapshot") == 0)
    return true;
  if (strncmp(name, "tpm", 3) == 0)
    return true;
  if (strncmp(name, "stp", 3) == 0)
    return true;

  if (strncmp(name, "rmnet_", 6) == 0 || strncmp(name, "ipa", 3) == 0 ||
      strncmp(name, "at_usb", 6) == 0 || strncmp(name, "at_mdm", 6) == 0 ||
      strncmp(name, "wwan_", 5) == 0 || strncmp(name, "btfmslim", 8) == 0 ||
      strncmp(name, "btpower", 7) == 0 || strncmp(name, "smd", 3) == 0 ||
      strncmp(name, "apr_", 4) == 0 || strstr(name, "aud_") != nullptr ||
      strstr(name, "icnss_") != nullptr)
    return true;

  if (strncmp(name, "hvc", 3) == 0 || strncmp(name, "gh_", 3) == 0)
    return true;

  if (strcmp(name, "audio_ipi") == 0 || strcmp(name, "scp_audio_ipi") == 0 ||
      strcmp(name, "vow") == 0 || strcmp(name, "vcp") == 0)
    return true;

  if (strncmp(name, "coresight", 9) == 0 ||
      strncmp(name, "remoteproc", 10) == 0 || strncmp(name, "rpmsg_", 6) == 0 ||
      strcmp(name, "cvp") == 0 || strncmp(name, "rdbg_", 5) == 0 ||
      strcmp(name, "dcc_sram") == 0 || strcmp(name, "spec_sync") == 0 ||
      strcmp(name, "synx_device") == 0)
    return true;

  if (strncmp(name, "anbox-", 6) == 0 || strcmp(name, "android_ssusbcon") == 0)
    return true;
  if (strncmp(name, "rpmb", 4) == 0)
    return true;
  if (strcmp(name, "mmp") == 0 || strcmp(name, "met") == 0)
    return true;
  if (strcmp(name, "mcupm") == 0 || strcmp(name, "sspm") == 0 ||
      strcmp(name, "scp") == 0)
    return true;
  if (strncmp(name, "aed", 3) == 0 && (name[3] == '\0' || isdigit(name[3])))
    return true;
  if (strncmp(name, "pmsg", 4) == 0)
    return true;
  if (strcmp(name, "mdp_sync") == 0 || strcmp(name, "fmt_sync") == 0 ||
      strcmp(name, "mtk_mdp") == 0 || strcmp(name, "mml_pq") == 0 ||
      strcmp(name, "sec_display_debug") == 0)
    return true;
  if (strcmp(name, "gps_emi") == 0 || strcmp(name, "gps_pwr") == 0)
    return true;
  if (strcmp(name, "goodix_fp") == 0 || strcmp(name, "k250a") == 0 ||
      strcmp(name, "drm_wv") == 0 || strcmp(name, "sec-nfc") == 0)
    return true;
  if (strcmp(name, "eara-io") == 0 || strcmp(name, "RT_Monitor") == 0 ||
      strcmp(name, "stats") == 0)
    return true;
  if (strncmp(name, "wmt", 3) == 0) 
    return true;
  if (strncmp(name, "fw_log_", 7) == 0 || strcmp(name, "sa_log_wifi") == 0)
    return true;
  if (strncmp(name, "sipa_", 5) == 0 || strcmp(name, "mddp") == 0 ||
      strcmp(name, "usip") == 0)
    return true;
  if (strncmp(name, "gpiochip", 8) == 0 || strncmp(name, "i2c-", 4) == 0 ||
      strncmp(name, "iio:device", 10) == 0)
    return true;
  if (strncmp(name, "cluster", 7) == 0 || strncmp(name, "gpu_freq", 8) == 0 ||
      strncmp(name, "cpu_online_", 11) == 0 ||
      strcmp(name, "memory_bandwidth") == 0 ||
      strstr(name, "msm_audio_ion") != nullptr ||
      strstr(name, "msm_hdcp") != nullptr || strstr(name, "msm_sps") != nullptr)
    return true;
  if (strncmp(name, "nr_", 3) == 0 || strncmp(name, "multipdp", 8) == 0 ||
      strncmp(name, "modem_boot", 10) == 0 || strcmp(name, "radio0") == 0)
    return true;
  if (strncmp(name, "bbd_", 4) == 0 || strncmp(name, "ssp_", 4) == 0 ||
      strcmp(name, "ssp_sensorhub") == 0)
    return true;
  if (strcmp(name, "mst_ctrl") == 0 || strncmp(name, "qbt", 3) == 0 ||
      strncmp(name, "dek_", 4) == 0)
    return true;
  if (strstr(name, "throughput") != nullptr || strstr(name, "latency") != nullptr)
    return true;
  if (strcmp(name, "fimg2d") == 0 || strcmp(name, "fmp") == 0 ||
      strcmp(name, "g2d") == 0 || strcmp(name, "vertex10") == 0 ||
      strcmp(name, "self_display") == 0)
    return true;
  if (strcmp(name, "ccic_misc") == 0 || strcmp(name, "hqm_event") == 0)
    return true;
  if (strstr(name, "multipdp") != nullptr || strncmp(name, "ttyBCM", 6) == 0)
    return true; 
  if (strcmp(name, "s5p-smem") == 0 || strncmp(name, "als_", 4) == 0)
    return true; 
  if (strstr(name, "throughput") != nullptr)
    return true; 

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