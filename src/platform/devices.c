#include "asc.h"

static int create_devices(const char *rootfs);
static bool is_dangerous_node(const char *name);
static void mirror_gpu_nodes(const char *dev_path);

/*
 * prune_host_devices()
 *
 * Scans the mounted /dev (devtmpfs) and unlinks dangerous nodes to isolate
 * the container from the host's display server, consoles, and GPU masters.
 */
static void prune_host_devices(const char *dev_path, const int privileged_mask) {
  if (privileged_mask & PRIV_UNFILT) {
    log_info("[SEC] --privileged=unfiltered-dev: skipping hardware blocklist.");
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
      /* Use force_unlink to handle potential bind-mount stale artifacts */
      umount2(path, MNT_DETACH);
      force_unlink(path);
      continue;
    }

    /* Subdirectory scanning for Tiers 1 and 2 (caps) */
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

        /* Special case: Handle /dev/dri/by-path symlinks */
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

  /* Ensure the directory exists */
  mkdir(dev_path, 0755);

  if (hw_access) {
    /* If hw_access is enabled, we mount host's devtmpfs.
     * WARNING: This is a shared singleton. We MUST be careful. */
    if (domount("devtmpfs", dev_path, "devtmpfs", MS_NOSUID | MS_NOEXEC,
                "mode=755") == 0) {
      /* On Android, /dev is a private tmpfs owned by ueventd - safe to modify.
       * On Linux, /dev is the host's shared devtmpfs (one instance,
       * kernel-managed). Unlinking nodes here removes them from the host
       * permanently. Skip on Linux. */
      prune_host_devices(dev_path, privileged_mask);

      /* devtmpfs is the kernel's own instance and does NOT contain nodes
       * that Android's ueventd created in its tmpfs-based /dev (kgsl-3d0,
       * mali0, dri/renderD128, etc.).  Mirror any missing GPU/hardware nodes
       * from the host into the freshly mounted devtmpfs now, before
       * create_devices() lays down the standard char nodes.
       * hw_access already implies full GPU wiring - no need to check gpu_mode
       * separately here. */
      mirror_gpu_nodes(dev_path);
    } else {
      log_warn("Failed to mount devtmpfs, falling back to tmpfs");
      if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
                  "size=8M,mode=755") < 0)
        return -1;
    }
  } else {
    /* Secure isolated /dev using tmpfs */
    if (domount("none", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC,
                "size=8M,mode=755") < 0)
      return -1;

    /* --gpu mode: scan the host /dev for known GPU "smoking guns" and mknod
     * the found nodes into our isolated tmpfs.  This gives GPU acceleration
     * without exposing the full host devtmpfs.  mirror_gpu_nodes() honours
     * the is_dangerous_node() blocklist and only creates character devices
     * that exist on the host, so it is safe to call unconditionally here. */
    if (gpu_mode) {
      log_info(
          "[GPU] --gpu mode: mirroring host GPU nodes into isolated tmpfs");
      mirror_gpu_nodes(dev_path);
    }
  }

  /* Create minimal set of device nodes (creates secure console/ptmx/etc.) */
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

  /* 1. Create standard devices */
  for (int i = 0; devices[i].name; i++) {
    snprintf(path, sizeof(path), "%s/dev/%s", rootfs, devices[i].name);

    /* We always force recreation of these critical standard nodes to ensure
     * correct permissions (0666) and isolation, even in unfiltered mode.
     * Host nodes in devtmpfs often have restrictive permissions that break
     * non-root users in the container. */
    force_unlink(path);

    if (mknod(path, devices[i].mode, devices[i].dev) < 0) {
      /* Fallback for environments where mknod is restricted */
      char host_path[PATH_MAX];
      snprintf(host_path, sizeof(host_path), "/dev/%s", devices[i].name);
      bind_mount(host_path, path);
    } else {
      chmod(path, devices[i].mode & 0777);
      /* Success! Now set ownership to root:tty (gid 5) for console/tty nodes */
      if (strcmp(devices[i].name, "console") == 0 ||
          strcmp(devices[i].name, "tty") == 0) {
        if (chown(path, 0, 5) < 0) {
          /* Ignore failure */
        }
      }
    }
  }

  /* 2. Create /dev/net/tun */
  snprintf(path, sizeof(path), "%s/dev/net", rootfs);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/dev/net/tun", rootfs);
  force_unlink(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 200)) < 0)
    bind_mount("/dev/net/tun", path);
  else
    chmod(path, 0666);

  /* 3. Create /dev/fuse */
  snprintf(path, sizeof(path), "%s/dev/fuse", rootfs);
  force_unlink(path);
  if (mknod(path, S_IFCHR | 0666, makedev(10, 229)) < 0)
    bind_mount("/dev/fuse", path);
  else
    chmod(path, 0666);

  /* Standard symlinks */
  char tgt[PATH_MAX];
  snprintf(tgt, sizeof(tgt), "%s/dev/fd", rootfs);
  if (symlink("/proc/self/fd", tgt) < 0 && errno != EEXIST)
    log_warn("Failed to create /dev/fd symlink: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdin", rootfs);
  if (symlink("/proc/self/fd/0", tgt) < 0 && errno != EEXIST)
    log_warn("Failed to create /dev/stdin symlink: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stdout", rootfs);
  if (symlink("/proc/self/fd/1", tgt) < 0 && errno != EEXIST)
    log_warn("Failed to create /dev/stdout symlink: %s", strerror(errno));

  snprintf(tgt, sizeof(tgt), "%s/dev/stderr", rootfs);
  if (symlink("/proc/self/fd/2", tgt) < 0 && errno != EEXIST)
    log_warn("Failed to create /dev/stderr symlink: %s", strerror(errno));

  return 0;
}

int setup_devpts(const bool hw_access) {
  const char *pts_path = "/dev/pts";

  /* Unmount any existing devpts instance first */
  umount2(pts_path, MNT_DETACH);

  /* Create mountpoint */
  mkdir(pts_path, 0755);

  /* Try mounting devpts with newinstance flag (CRITICAL for private PTYs) */
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
    if (domount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, opts[i]) ==
        0) {
      /* Setup /dev/ptmx to point to the new pts/ptmx */
      const char *ptmx_path = "/dev/ptmx";
      const char *pts_ptmx = "/dev/pts/ptmx";

      if (hw_access) {
        /* In HW access mode, /dev is a devtmpfs (shared singleton).
         * CRITICAL: Do NOT unlink. create_devices() already created
         * a real char device node (5,2) for us to bind-mount over. */
        if (mount(pts_ptmx, ptmx_path, nullptr, MS_BIND, nullptr) == 0) {
          return 0;
        }
      } else {
        /* Secure mode: /dev is a private tmpfs. Unlink is safe. */
        unlink(ptmx_path);

        /* Method 1: Bind mount (preferred) */
        if (write_file(ptmx_path, "") == 0) {
          if (mount(pts_ptmx, ptmx_path, nullptr, MS_BIND, nullptr) == 0) {
            return 0;
          }
        }

        /* Method 2: Symlink - but verify target exists first.
         * Kernel 3.x devpts newinstance may not create /dev/pts/ptmx. */
        unlink(ptmx_path);
        if (symlink("pts/ptmx", ptmx_path) == 0 && access(pts_ptmx, F_OK) == 0)
          return 0;

        /* Method 3: real c 5,2 node for kernel 3.x (not namespace-isolated
         * but /dev/ptmx actually exists and openpty works). */
        unlink(ptmx_path);
        if (mknod(ptmx_path, S_IFCHR | 0666, makedev(5, 2)) == 0) {
          chmod(ptmx_path, 0666);
          return 0;
        }
      }

      log_warn("Failed to virtualize /dev/ptmx, PTYs might not work");
      return 0;
    }
  }

  log_error("Failed to mount devpts with newinstance flag");
  return -1;
}

/* Ensure host devpts is mounted - specifically for Android Recovery
 * environments where /dev/pts is often missing or unmounted, causing openpty()
 * to fail. */
int fix_host_ptys(void) {
  const char *pts_path = "/dev/pts";

  /* If already a mountpoint, we are good */
  if (is_mountpoint(pts_path))
    return 0;

  /* Ensure directory exists */
  mkdir(pts_path, 0755);

  /* Mount host devpts. We use standard gid=5 (tty) and mode=620.
   * This is the 'host' global namespace version of setup_devpts. */
  if (mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC,
            "gid=5,mode=620") < 0) {
    if (errno != EBUSY) {
      /* EBUSY means already mounted (redundant with is_mountpoint but safe) */
      log_warn("Failed to mount host devpts: %s", strerror(errno));
      return -1;
    }
  }

  log_info("Host devpts mounted successfully (Recovery fix).");
  return 0;
}

/*
 * 共享的 GPU/硬件设备列表。
 *
 * mirror_gpu_nodes() 会遍历这些表。
 * 在此统一添加新设备，函数会自动识别并处理它们。
 */

/* Dynamic directories: { host_dir, prefix_or_NULL } */
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
  {nullptr, nullptr}, /* sentinel */
};

/* Static paths: individual nodes that don't fit a directory scan */
static const char *gpu_static_devices[] = {
  /* Android IPC (Critical for Android containers/hosts) */
  "/dev/binder",
  "/dev/vndbinder",
  "/dev/hwbinder",

  /* Legacy Android Memory Allocators */
  "/dev/ion",
  "/dev/ashmem",

  /* ARM Mali / Adreno aliases */
  "/dev/mali",
  "/dev/genlock",

  /* AMD ROCm Compute */
  "/dev/kfd",

  /* PowerVR */
  "/dev/pvrsrvkm",
  "/dev/pvr_sync",

  /* Tegra */
  "/dev/nvhost-ctrl",
  "/dev/nvhost-gpu",
  "/dev/nvhost-ctrl-gpu",
  "/dev/nvhost-as-gpu",
  "/dev/nvhost-dbg-gpu",
  "/dev/nvhost-prof-gpu",
  "/dev/nvhost-tsg",
  "/dev/nvhost-tsg-gpu",
  "/dev/nvhost-vic",
  "/dev/nvhost-nvdec",
  "/dev/nvhost-nvdec1",
  "/dev/nvhost-nvenc",
  "/dev/nvhost-msenc",
  "/dev/nvmap",

  /* WSL2 */
  "/dev/dxg",

  /* Async Sync */
  "/dev/sw_sync",

  nullptr, /* sentinel */
};

/*
 * is_dangerous_node()
 *
 * Checks if a device node name is "dangerous" (part of the host display stack
 * or a privileged DRM master node) and should be blocked from container access.
 */
static bool is_dangerous_node(const char *name) {
  /* Tier 1: DRM card nodes and control nodes */
  if ((strncmp(name, "card", 4) == 0 &&
       (name[4] == '\0' || isdigit(name[4]))) ||
      (strncmp(name, "controlD", 8) == 0 &&
       (name[8] == '\0' || isdigit(name[8])))) {
    return true;
  }

  /* Tier 2: NVIDIA Proprietary Master & Modeset Nodes */
  if (strcmp(name, "nvidiactl") == 0 || strcmp(name, "nvidia-modeset") == 0)
    return true;
  /* Block raw GPU nodes /dev/nvidia0, nvidia1, etc. */
  if (strncmp(name, "nvidia", 6) == 0 && isdigit(name[6]))
    return true;
  /* Block NVIDIA capability nodes */
  if (strncmp(name, "nvidia-cap", 10) == 0)
    return true;

  /* Tier 3 & 4: VGA Arbiter and Framebuffers */
  if (strcmp(name, "vga_arbiter") == 0)
    return true;
  if (strncmp(name, "fb", 2) == 0 && isdigit(name[2]))
    return true;

  /* Tier 5: Host TTY nodes
   *
   * SAFE (pass through - legitimate dev/embedded devices):
   *   ttyUSB*  USB-to-serial adapters (FTDI, CH340, CP2102, PL2303)
   *   ttyACM*  USB CDC ACM (Arduino, ESP32-C3/S2, Pi Pico, STM32, Heimdall)
   *   ttyAMA*  ARM AMBA UART (Raspberry Pi GPIO serial, ARM SoC hardware UART)
   *   ttyTHS*  NVIDIA Tegra high-speed UART (Jetson boards)
   *   ttymxc*  NXP i.MX UART (embedded SBCs)
   *
   * DANGEROUS (block - host console/modem paths):
   *   ttyN     VT masters: DRM Master handover risk on VT switch
   *   ttyS*    x86 hardware serial console (COM1/COM2)
   *   ttyGS*   USB gadget serial (host-side gadget controller)
   *   ttyHSL*  Qualcomm high-speed UART (modem console)
   *   ttyMSM*  Qualcomm MSM serial console
   *
   * Unknown tty* nodes fall through as safe (dev-friendly default). */
  if (strncmp(name, "tty", 3) == 0) {
    /* Safe: check before any block rule */
    if (strncmp(name, "ttyUSB", 6) == 0 || strncmp(name, "ttyACM", 6) == 0 ||
        strncmp(name, "ttyAMA", 6) == 0 || strncmp(name, "ttyTHS", 6) == 0 ||
        strncmp(name, "ttymxc", 6) == 0)
      return false;
    /* Dangerous: VT masters */
    if (isdigit(name[3]))
      return true;
    /* Everything else is dangerous.
     * Android kernels register hundreds of tty* nodes for virtual UARTs,
     * modem channels (ttyCMIPC*), AT command interfaces (ttyC_AT), and
     * arbitrary vendor UART drivers (ttya*..ttyz*, ttyC*, ttyb*, etc.).
     * The old "unknown = safe" default was the bug - on Android the correct
     * default is BLOCKED.  Explicit safe entries above still pass through. */
    return true;
  }

  /* Tier 6: MediaTek Modem & Legacy BSD PTYs */
  if (strncmp(name, "ccci", 4) == 0 || strncmp(name, "umts_", 5) == 0)
    return true;
  if (strncmp(name, "pty", 3) == 0) /* BSD PTY masters */
    return true;

  /* Tier 7: Input Injection & RF Kill */
  if (strcmp(name, "uinput") == 0 || strcmp(name, "rfkill") == 0)
    return true;

  /* Tier 8: TEE, Connectivity & Power Management (Android/MTK) */
  if (strncmp(name, "tz", 2) == 0 || strncmp(name, "trusty", 6) == 0 ||
      strncmp(name, "gz_", 3) == 0 || strncmp(name, "tee", 3) == 0)
    return true; /* TrustZone / TEE / Secure OS */
  if (strncmp(name, "conn", 4) == 0 || strcmp(name, "mtk_sec") == 0)
    return true; /* MediaTek Connectivity & Security */
  if (strncasecmp(name, "mt_pmic", 7) == 0)
    return true; /* Power Management IC */
  if (strcmp(name, "tuihw") == 0 || strcmp(name, "wlan") == 0)
    return true;

  /* Tier 9: Legacy Clutter */
  if (strncmp(name, "ram", 3) == 0 && isdigit(name[3]))
    return true; /* Legacy RAM disks */

  /* Tier 10: Core virtualized nodes (should be unlinked and recreated) */
  if (strcmp(name, "console") == 0 || strcmp(name, "tty") == 0 ||
      strcmp(name, "full") == 0 || strcmp(name, "null") == 0 ||
      strcmp(name, "zero") == 0 || strcmp(name, "random") == 0 ||
      strcmp(name, "urandom") == 0 || strcmp(name, "ptmx") == 0 ||
      strcmp(name, "initctl") == 0)
    return true;

  /* Systemic Hardening (Phase 12) */
  /* Tier 10: Direct Host Access */
  if (strcmp(name, "mem") == 0 || strcmp(name, "kmem") == 0 ||
      strcmp(name, "port") == 0 || strcmp(name, "kmsg") == 0)
    return true;
  /* Tier 11: DisplayPort Aux */
  if (strncmp(name, "drm_dp_aux", 10) == 0)
    return true;
  /* Tier 12: Virtual Consoles */
  if (strncmp(name, "vcs", 3) == 0)
    return true;
  /* Tier 13: Watchdogs */
  if (strstr(name, "watchdog") != nullptr)
    return true;

  /* Tier 13.5: Qualcomm RPC & Secure Interfaces */
  if (strstr(name, "qseecom") != nullptr || strstr(name, "smcinvoke") != nullptr ||
      strstr(name, "adsprpc") != nullptr)
    return true;

  /* Tier 14: DMA/Memory Gaps */
  if (strcmp(name, "udmabuf") == 0 || strcmp(name, "snapshot") == 0)
    return true;
  /* Tier 15: TPM */
  if (strncmp(name, "tpm", 3) == 0)
    return true;
  /* Tier 16: MTK STP Combo Chip Bus (BT/GPS/WiFi transport) */
  if (strncmp(name, "stp", 3) == 0)
    return true;

  /* Tier 16.5: Qualcomm / Modem Connectivity Loopholes */
  if (strncmp(name, "rmnet_", 6) == 0 || strncmp(name, "ipa", 3) == 0 ||
      strncmp(name, "at_usb", 6) == 0 || strncmp(name, "at_mdm", 6) == 0 ||
      strncmp(name, "wwan_", 5) == 0 || strncmp(name, "btfmslim", 8) == 0 ||
      strncmp(name, "btpower", 7) == 0 || strncmp(name, "smd", 3) == 0 ||
      strncmp(name, "apr_", 4) == 0 || strstr(name, "aud_") != nullptr ||
      strstr(name, "icnss_") != nullptr)
    return true;

  /* Tier 16.6: Hypervisor Consoles & Virtio Loopbacks */
  if (strncmp(name, "hvc", 3) == 0 || strncmp(name, "gh_", 3) == 0)
    return true;

  /* Tier 17: MTK Audio IPI / SCP IPC - known exploitable attack surface */
  if (strcmp(name, "audio_ipi") == 0 || strcmp(name, "scp_audio_ipi") == 0 ||
      strcmp(name, "vow") == 0 || strcmp(name, "vcp") == 0)
    return true;

  /* Tier 17.5: Qualcomm SoC Tracing & DSP Debug */
  if (strncmp(name, "coresight", 9) == 0 ||
      strncmp(name, "remoteproc", 10) == 0 || strncmp(name, "rpmsg_", 6) == 0 ||
      strcmp(name, "cvp") == 0 || strncmp(name, "rdbg_", 5) == 0 ||
      strcmp(name, "dcc_sram") == 0 || strcmp(name, "spec_sync") == 0 ||
      strcmp(name, "synx_device") == 0)
    return true;

  /* Tier 17.6: Android-Specific Compatibility Nodes (Anbox, etc.) */
  if (strncmp(name, "anbox-", 6) == 0 || strcmp(name, "android_ssusbcon") == 0)
    return true;

  /* Tier 18: eMMC Replay-Protected Memory Block - stores DRM/boot keys */
  if (strncmp(name, "rpmb", 4) == 0)
    return true;

  /* Tier 19: MTK Multimedia Profiler + Event Tracer (CMDQ-class IOCTL risk) */
  if (strcmp(name, "mmp") == 0 || strcmp(name, "met") == 0)
    return true;

  /* Tier 20: MTK Co-Processor Firmware IPC Channels */
  if (strcmp(name, "mcupm") == 0 || strcmp(name, "sspm") == 0 ||
      strcmp(name, "scp") == 0)
    return true;

  /* Tier 21: MTK AED kernel exception daemon nodes */
  if (strncmp(name, "aed", 3) == 0 && (name[3] == '\0' || isdigit(name[3])))
    return true;

  /* Tier 22: Persistent RAM log writer (survives reboots, destroys host
   * diagnostics) */
  if (strncmp(name, "pmsg", 4) == 0)
    return true;

  /* Tier 23: MTK Display Pipeline Sync (display-critical fence driver) */
  if (strcmp(name, "mdp_sync") == 0 || strcmp(name, "fmt_sync") == 0 ||
      strcmp(name, "mtk_mdp") == 0 || strcmp(name, "mml_pq") == 0 ||
      strcmp(name, "sec_display_debug") == 0)
    return true;

  /* Tier 24: GPS co-processor shared memory + power control */
  if (strcmp(name, "gps_emi") == 0 || strcmp(name, "gps_pwr") == 0)
    return true;

  /* Tier 25: Secure elements, biometrics, DRM key nodes */
  if (strcmp(name, "goodix_fp") == 0 || strcmp(name, "k250a") == 0 ||
      strcmp(name, "drm_wv") == 0 || strcmp(name, "sec-nfc") == 0)
    return true;

  /* Tier 26: MTK debug/tracing nodes and QCOM/Other misc */
  if (strcmp(name, "eara-io") == 0 || strcmp(name, "RT_Monitor") == 0 ||
      strcmp(name, "stats") == 0)
    return true;
  if (strncmp(name, "wmt", 3) == 0) /* wmtdetect, wmtWifi, wmtNfc, etc. */
    return true;

  /* Tier 27: MTK firmware log exporters */
  if (strncmp(name, "fw_log_", 7) == 0 || strcmp(name, "sa_log_wifi") == 0)
    return true;

  /* Tier 28: MTK Network Offload & USB IP Accelerators
   * sipa_*: bypasses netfilter at hardware offload layer.
   * mddp: MTK Distributed Data Path offload control. */
  if (strncmp(name, "sipa_", 5) == 0 || strcmp(name, "mddp") == 0 ||
      strcmp(name, "usip") == 0)
    return true;

  /* Tier 29: Direct Bus Access (Exynos/Samsung)
   * gpiochip*: Raw GPIO control of motherboard pins.
   * i2c-*: Raw I2C bus access to CMOS sensors, power chips, and touchscreens.
   * iio:device*: Industrial I/O for raw ADC/Sensor data. */
  if (strncmp(name, "gpiochip", 8) == 0 || strncmp(name, "i2c-", 4) == 0 ||
      strncmp(name, "iio:device", 10) == 0)
    return true;

  /* Tier 30: Performance & Clock Scaling
   * Cluster/GPU/Memory frequency overrides allow host sabotage. */
  if (strncmp(name, "cluster", 7) == 0 || strncmp(name, "gpu_freq", 8) == 0 ||
      strncmp(name, "cpu_online_", 11) == 0 ||
      strcmp(name, "memory_bandwidth") == 0 ||
      strstr(name, "msm_audio_ion") != nullptr ||
      strstr(name, "msm_hdcp") != nullptr || strstr(name, "msm_sps") != nullptr)
    return true;

  /* Tier 31: Exynos Modem & Multi-PDP
   * NR (5G) and Multi-PDP packet bridges for Samsung modems. */
  if (strncmp(name, "nr_", 3) == 0 || strncmp(name, "multipdp", 8) == 0 ||
      strncmp(name, "modem_boot", 10) == 0 || strcmp(name, "radio0") == 0)
    return true;

  /* Tier 32: Sensor Hub & DSPs
   * BBD: Big Brother Daemon (Exynos sensor hub).
   * SSP: Samsung Sensor Processor. */
  if (strncmp(name, "bbd_", 4) == 0 || strncmp(name, "ssp_", 4) == 0 ||
      strcmp(name, "ssp_sensorhub") == 0)
    return true;

  /* Tier 33: Samsung Specific Hardware (Payment/Security)
   * MST: Samsung Pay Magnetic Secure Transmission.
   * QBT: Samsung Ultrasonic Fingerprint (Qualcomm/Samsung hybrid).
   * DEK: Data Encryption Keys. */
  if (strcmp(name, "mst_ctrl") == 0 || strncmp(name, "qbt", 3) == 0 ||
      strncmp(name, "dek_", 4) == 0)
    return true;

  /* Tier 34: Throughput & Latency Monitoring
   * Removes dozens of performance tracking nodes from /dev listing. */
  if (strstr(name, "throughput") != nullptr || strstr(name, "latency") != nullptr)
    return true;

  /* Tier 35: Exynos Multimedia & Misc Logic
   * FIMG2D/G2D: Graphics accelerators that don't use DRM/RenderNodes.
   * Vertex10: Proprietary hardware logic. */
  if (strcmp(name, "fimg2d") == 0 || strcmp(name, "fmp") == 0 ||
      strcmp(name, "g2d") == 0 || strcmp(name, "vertex10") == 0 ||
      strcmp(name, "self_display") == 0)
    return true;

  /* Tier 36: Misc Samsung Utility Nodes */
  if (strcmp(name, "ccic_misc") == 0 || strcmp(name, "hqm_event") == 0)
    return true;

  /* Tier 37: Exynos/Samsung specific */
  if (strstr(name, "multipdp") != nullptr || strncmp(name, "ttyBCM", 6) == 0)
    return true; /* Catch dymmy/dummy and Broadcom consoles */
  if (strcmp(name, "s5p-smem") == 0 || strncmp(name, "als_", 4) == 0)
    return true; /* Shared memory and raw sensors */
  if (strstr(name, "throughput") != nullptr)
    return true; /* Global throughput monitoring cleanup */

  return false;
}

/*
 * mirror_gpu_node()
 *
 * 针对单个宿主机 GPU 设备路径：如果该节点在容器的 /dev 中缺失，或者错误地
 * 成为一个目录，则使用 mknod() 进行修复。
 *
 * 背景：在 Android 上，/dev 是由 ueventd 填充的普通 tmpfs - 而不是
 * 内核的 devtmpfs。因此，像 /dev/kgsl-3d0、/dev/mali0 和
 * /dev/dri/renderD128 这样的 GPU 节点存在于 ueventd 的 tmpfs 中，但当我们在
 * 容器内挂载一个全新的 devtmpfs 时，它们却缺失了（或者显示为空目录）。
 * 在此我们只需确保容器的 /dev 中存在正确的字符设备节点即可。
 */
static void mirror_gpu_node(const char *host_path, const char *dev_path) {
  /* host_path must be rooted under /dev/ */
  if (strncmp(host_path, "/dev/", 5) != 0)
    return;

  /* Trusted GPU list gate: never mirror dangerous/sensitive nodes.
   * This check lives here - not only in callers - so every code path
   * (dynamic dir scan AND static list) is covered by one consistent rule. */
  const char *node_name = strrchr(host_path, '/');
  node_name = node_name ? node_name + 1 : host_path;
  if (is_dangerous_node(node_name))
    return;

  /* Host node must be a character device.  Applies to BOTH root-owned
   * (gid=0) and group-owned nodes - we do not filter by ownership here.
   * add_gpu_gid() skips gid=0 because there is nothing to add to the
   * group list, but mirroring must still happen so the node is physically
   * present in devtmpfs regardless of who owns it. */
  struct stat host_st;
  if (stat(host_path, &host_st) < 0)
    return;
  if (!S_ISCHR(host_st.st_mode))
    return;

  /* Build the container-side target path */
  const char *rel = host_path + 5; /* strip leading "/dev/" */
  char tgt[PATH_MAX];
  snprintf(tgt, sizeof(tgt), "%s/%s", dev_path, rel);

  /* Ensure the parent directory exists (handles /dev/dri/renderD128 etc.) */
  char parent[PATH_MAX];
  snprintf(parent, sizeof(parent), "%s", tgt);
  char *slash = strrchr(parent, '/');
  if (slash && slash != parent) {
    *slash = '\0';
    mkdir(parent, 0755); /* best-effort - already exists is fine */
  }

  /* Check current state of the target */
  struct stat tgt_st;
  if (lstat(tgt, &tgt_st) == 0) {
    if (S_ISCHR(tgt_st.st_mode)) {
      /* devtmpfs already has a proper node. Re-own it to root:root with
       * 0666 mode so the container user can access it regardless of
       * the host GID. */
      if (chown(tgt, 0, 0) < 0)
        log_warn("[GPU] chown (pre-existing) %s → root:root: %s", tgt,
                 strerror(errno));
      chmod(tgt, 0666);
      return;
    }

    /* devtmpfs created an empty directory placeholder instead of a node
     * (the /dev/kgsl-3d0 case seen in the screenshot).  Nuke it. */
    if (S_ISDIR(tgt_st.st_mode)) {
      if (rmdir(tgt) < 0) {
        log_warn("[GPU] Cannot remove stale directory %s: %s", tgt,
                 strerror(errno));
        return;
      }
    } else {
      unlink(tgt);
    }
  }

  /* Create the node with the same major:minor and permissions as the host */
  const mode_t mode = S_IFCHR | (host_st.st_mode & 0666);
  if (mknod(tgt, mode, host_st.st_rdev) < 0) {
    log_warn("[GPU] mknod %s (%d:%d) failed: %s", tgt,
             (int)major(host_st.st_rdev), (int)minor(host_st.st_rdev),
             strerror(errno));
    return;
  }

  /* Force ownership to root:root with 0666 mode so UID 1000 can
   * access the node regardless of which GID the host assigned to it. */
  if (chown(tgt, 0, 0) < 0)
    log_warn("[GPU] chown %s → root:root: %s", tgt, strerror(errno));
  chmod(tgt, 0666);

  log_info("[GPU] Mirrored missing node: %-30s (%d:%d)", tgt,
           (int)major(host_st.st_rdev), (int)minor(host_st.st_rdev));
}

/*
 * do_mirror_gpu_dir()
 *
 * Walk a host directory (e.g. /dev/dri, /dev/dma_heap) and call
 * mirror_gpu_node() for every entry that matches the optional prefix.
 *
 * We deliberately do NOT pre-filter by d_type here.  d_type can be
 * DT_UNKNOWN on some Android kernels/filesystems, which would silently
 * drop valid root-owned char devices before mirror_gpu_node() ever sees
 * them.  mirror_gpu_node() already does a stat()+S_ISCHR check and the
 * is_dangerous_node() gate - those are the single source of truth.
 */
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

/*
 * mirror_gpu_nodes()
 *
 * 公共入口点，在挂载 devtmpfs 后立即从 setup_dev() 调用。
 * 镜像在表中定义的每个 GPU/硬件设备节点。
 *
 * 必须在 pivot_root 之前，且宿主机的 /dev 仍然可访问时调用。
 */
static void mirror_gpu_nodes(const char *dev_path) {
  /* Dynamic directories */
  for (int i = 0; gpu_scan_dirs[i].dir != nullptr; i++)
    do_mirror_gpu_dir(gpu_scan_dirs[i].dir, gpu_scan_dirs[i].prefix, dev_path);

  /* Static individual nodes */
  for (int i = 0; gpu_static_devices[i] != nullptr; i++)
    mirror_gpu_node(gpu_static_devices[i], dev_path);
}
