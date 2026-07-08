#include "asc.h"

static int create_devices(const char *rootfs);
static void mirror_gpu_nodes(const char *dev_path);

int setup_dev(const char *rootfs, const bool gpu_mode, const int privileged_mask) {
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
  std::string_view sv_name{name};

  if ((sv_name.starts_with("card") &&
       (name[4] == '\0' || isdigit(name[4]))) ||
      (sv_name.starts_with("controlD") &&
       (name[8] == '\0' || isdigit(name[8])))) {
    return true;
  }

  if (strcmp(name, "nvidiactl") == 0 || strcmp(name, "nvidia-modeset") == 0)
    return true;
  if (sv_name.starts_with("nvidia") && isdigit(name[6]))
    return true;
  if (sv_name.starts_with("nvidia-cap"))
    return true;

  if (strcmp(name, "vga_arbiter") == 0)
    return true;
  if (sv_name.starts_with("fb") && isdigit(name[2]))
    return true;

  if (sv_name.starts_with("tty")) {
    if (sv_name.starts_with("ttyUSB") || sv_name.starts_with("ttyACM") ||
        sv_name.starts_with("ttyAMA") || sv_name.starts_with("ttyTHS") ||
        sv_name.starts_with("ttymxc"))
      return false;
    if (isdigit(name[3]))
      return true;
    return true;
  }

  if (sv_name.starts_with("ccci") || sv_name.starts_with("umts_"))
    return true;
  if (sv_name.starts_with("pty")) 
    return true;
  if (strcmp(name, "uinput") == 0 || strcmp(name, "rfkill") == 0)
    return true;
  if (sv_name.starts_with("tz") || sv_name.starts_with("trusty") ||
      sv_name.starts_with("gz_") || sv_name.starts_with("tee"))
    return true; 
  if (sv_name.starts_with("conn") || strcmp(name, "mtk_sec") == 0)
    return true; 
  if (strncasecmp(name, "mt_pmic", 7) == 0)
    return true; 
  if (strcmp(name, "tuihw") == 0 || strcmp(name, "wlan") == 0)
    return true;
  if (sv_name.starts_with("ram") && isdigit(name[3]))
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
  if (sv_name.starts_with("drm_dp_aux"))
    return true;
  if (sv_name.starts_with("vcs"))
    return true;
  if (strstr(name, "watchdog") != nullptr)
    return true;

  if (strstr(name, "qseecom") != nullptr || strstr(name, "smcinvoke") != nullptr ||
      strstr(name, "adsprpc") != nullptr)
    return true;

  if (strcmp(name, "udmabuf") == 0 || strcmp(name, "snapshot") == 0)
    return true;
  if (sv_name.starts_with("tpm"))
    return true;
  if (sv_name.starts_with("stp"))
    return true;

  if (sv_name.starts_with("rmnet_") || sv_name.starts_with("ipa") ||
      sv_name.starts_with("at_usb") || sv_name.starts_with("at_mdm") ||
      sv_name.starts_with("wwan_") || sv_name.starts_with("btfmslim") ||
      sv_name.starts_with("btpower") || sv_name.starts_with("smd") ||
      sv_name.starts_with("apr_") || strstr(name, "aud_") != nullptr ||
      strstr(name, "icnss_") != nullptr)
    return true;

  if (sv_name.starts_with("hvc") || sv_name.starts_with("gh_"))
    return true;

  if (strcmp(name, "audio_ipi") == 0 || strcmp(name, "scp_audio_ipi") == 0 ||
      strcmp(name, "vow") == 0 || strcmp(name, "vcp") == 0)
    return true;

  if (sv_name.starts_with("coresight") ||
      sv_name.starts_with("remoteproc") || sv_name.starts_with("rpmsg_") ||
      strcmp(name, "cvp") == 0 || sv_name.starts_with("rdbg_") ||
      strcmp(name, "dcc_sram") == 0 || strcmp(name, "spec_sync") == 0 ||
      strcmp(name, "synx_device") == 0)
    return true;

  if (sv_name.starts_with("anbox-") || strcmp(name, "android_ssusbcon") == 0)
    return true;
  if (sv_name.starts_with("rpmb"))
    return true;
  if (strcmp(name, "mmp") == 0 || strcmp(name, "met") == 0)
    return true;
  if (strcmp(name, "mcupm") == 0 || strcmp(name, "sspm") == 0 ||
      strcmp(name, "scp") == 0)
    return true;
  if (sv_name.starts_with("aed") && (name[3] == '\0' || isdigit(name[3])))
    return true;
  if (sv_name.starts_with("pmsg"))
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
  if (sv_name.starts_with("wmt")) 
    return true;
  if (sv_name.starts_with("fw_log_") || strcmp(name, "sa_log_wifi") == 0)
    return true;
  if (sv_name.starts_with("sipa_") || strcmp(name, "mddp") == 0 ||
      strcmp(name, "usip") == 0)
    return true;
  if (sv_name.starts_with("gpiochip") || sv_name.starts_with("i2c-") ||
      sv_name.starts_with("iio:device"))
    return true;
  if (sv_name.starts_with("cluster") || sv_name.starts_with("gpu_freq") ||
      sv_name.starts_with("cpu_online_") ||
      strcmp(name, "memory_bandwidth") == 0 ||
      strstr(name, "msm_audio_ion") != nullptr ||
      strstr(name, "msm_hdcp") != nullptr || strstr(name, "msm_sps") != nullptr)
    return true;
  if (sv_name.starts_with("nr_") || sv_name.starts_with("multipdp") ||
      sv_name.starts_with("modem_boot") || strcmp(name, "radio0") == 0)
    return true;
  if (sv_name.starts_with("bbd_") || sv_name.starts_with("ssp_") ||
      strcmp(name, "ssp_sensorhub") == 0)
    return true;
  if (strcmp(name, "mst_ctrl") == 0 || sv_name.starts_with("qbt") ||
      sv_name.starts_with("dek_"))
    return true;
  if (strstr(name, "throughput") != nullptr || strstr(name, "latency") != nullptr)
    return true;
  if (strcmp(name, "fimg2d") == 0 || strcmp(name, "fmp") == 0 ||
      strcmp(name, "g2d") == 0 || strcmp(name, "vertex10") == 0 ||
      strcmp(name, "self_display") == 0)
    return true;
  if (strcmp(name, "ccic_misc") == 0 || strcmp(name, "hqm_event") == 0)
    return true;
  if (strstr(name, "multipdp") != nullptr || sv_name.starts_with("ttyBCM"))
    return true; 
  if (strcmp(name, "s5p-smem") == 0 || sv_name.starts_with("als_"))
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