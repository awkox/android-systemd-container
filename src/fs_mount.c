#include "asc.h"

/* ---------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------------*/

/* Check if a path is a mountpoint */
bool is_mountpoint(const char *path) {
  struct stat st1, st2;
  if (stat(path, &st1) < 0)
    return false;

  char parent[PATH_MAX];
  snprintf(parent, sizeof(parent), "%.4092s/..", path);
  if (stat(parent, &st2) < 0)
    return false;

  return st1.st_dev != st2.st_dev;
}

/* Find available mount point in /tmp/ds-fork/mnt/ using container name.
 * If a mount point already exists for this name but is not associated
 * with an active container (stale), it will be cleaned up. */
static int find_available_mountpoint(const char *name, char *mount_path,
                                     const size_t size) {
  const char *base_dir = IMG_MOUNT_ROOT;

  /* Create base directory if it doesn't exist */
  mkdir(base_dir, 0755);

  char safe_name[256];
  sanitize_container_name(name, safe_name, sizeof(safe_name));

  snprintf(mount_path, size, "%s/%s", base_dir, safe_name);

  if (access(mount_path, F_OK) == 0) {
    if (is_mountpoint(mount_path)) {
      /* This is a stale mount point from a previous crashed run.
       * (We know it's stale because start_rootfs ensures the container name
       * itself is unique among currently running containers). */
      log_warn("Found stale mount at %s, cleaning up...", mount_path);
      if (umount2(mount_path, MNT_DETACH) < 0) {
        /* umount2 failed: find and detach the backing loop device explicitly */
        char stale_dev[256] = {0};
        get_backing_dev(mount_path, stale_dev, sizeof(stale_dev));
        umount2(mount_path, MNT_DETACH | MNT_FORCE);
        if (stale_dev[0])
          loop_detach(stale_dev);
      }
    }
    return 0;
  }

  if (mkdir(mount_path, 0755) < 0) {
    log_error("Failed to create mount directory %s: %s", mount_path,
              strerror(errno));
    return -1;
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * Generic mount wrappers
 * ---------------------------------------------------------------------------*/

int domount(const char *src, const char *tgt, const char *fstype,
            const unsigned long flags, const char *data) {
  if (mount(src, tgt, fstype, flags, data) < 0) {
    /* Don't log if it's already mounted (EBUSY) */
    if (errno != EBUSY) {
      log_error("Failed to mount %s on %s (%s): %s", src ? src : "none", tgt,
                fstype ? fstype : "none", strerror(errno));
      return -1;
    }
  }
  return 0;
}

int bind_mount(const char *src, const char *tgt) {
  auto_close const int src_fd = open(src, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  if (src_fd < 0) {
    /* If it failed because of ELOOP, it's a symlink we should reject anyway */
    return -1;
  }

  struct stat st_src;
  if (fstat(src_fd, &st_src) < 0)
    return -1;

  /* Reject symlinks explicitly */
  if (S_ISLNK(st_src.st_mode)) {
    errno = ELOOP;
    return -1;
  }

  struct stat st_tgt;
  if (lstat(tgt, &st_tgt) < 0) {
    /* Target does not exist — reject if any parent component is a symlink
     * (lstat only protects the final component from being followed). */
    if (path_has_symlink(tgt)) {
      log_error("Security Violation: symlink in bind target path %s", tgt);
      errno = ELOOP;
      return -1;
    }
    if (S_ISDIR(st_src.st_mode)) {
      mkdir(tgt, st_src.st_mode & 07777);
      if (chown(tgt, st_src.st_uid, st_src.st_gid) < 0) {
        /* ignore chown failure, not critical for bind mount setup */
      }
    } else {
      write_file(tgt, "");
    }
  } else if (S_ISLNK(st_tgt.st_mode)) {
    log_error("Security Violation: Bind target %s is a symlink!", tgt);
    errno = ELOOP;
    return -1;
  }

  char proc_path[64];
  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", src_fd);

  return domount(proc_path, tgt, nullptr, MS_BIND | MS_REC, nullptr);
}



/* ---------------------------------------------------------------------------
 * /dev setup
 * ---------------------------------------------------------------------------*/

int check_volatile_mode(cfg_t *cfg) {
  if (!cfg->volatile_mode)
    return 0;

  if (grep_file("/proc/filesystems", "overlay") != 1) {
    log_error("OverlayFS is not supported by your kernel. Volatile mode cannot "
              "be used.");
    return -1;
  }

  /* Pre-flight: reject f2fs lowerdir - known Android kernel limitation */
  struct statfs sfs;
  if (statfs(cfg->img_mount_point, &sfs) == 0 && sfs.f_type == 0xF2F52010) {
    log_error("Volatile mode cannot be used: Your rootfs is on f2fs, which is "
              "not supported as an OverlayFS lower layer on most Android "
              "kernels.");
    log_error("Tip: Use a rootfs image (-i) instead of a directory (-r) "
              "for volatile mode on f2fs partitions.");
    return -1;
  }

  return 0;
}

int setup_volatile_overlay(cfg_t *cfg) {
  /* 1. Create temporary workspace in ds-fork/Volatile/<name> */
  char base[PATH_MAX];
  snprintf(base, sizeof(base), "%s/" RUNTIME_VOLATILE_SUBDIR "/%s",
           get_runtime_dir(), cfg->container_name);
  if (mkdir_p(base, 0755) < 0) {
    log_error("Failed to create volatile workspace: %s", base);
    return -1;
  }
  safe_strncpy(cfg->volatile_dir, base, sizeof(cfg->volatile_dir));

  /* 2. Mount tmpfs as the backing store for upper/work */
  if (domount("none", base, "tmpfs", 0, "size=50%,mode=755") < 0)
    return -1;

  /* 3. Create subdirectories */
  char upper[PATH_MAX + 32], work[PATH_MAX + 32], merged[PATH_MAX + 32];
  snprintf(upper, sizeof(upper), "%s/upper", base);
  snprintf(work, sizeof(work), "%s/work", base);
  snprintf(merged, sizeof(merged), "%s/merged", base);
  mkdir(upper, 0755);
  mkdir(work, 0755);
  mkdir(merged, 0755);

  /* 4. Perform Overlay mount */
  char opts[32768];
  const int n = snprintf(opts, sizeof(opts),
    "lowerdir=%s,upperdir=%s/upper,workdir=%s/work,context=\""
    ANDROID_TMPFS_CONTEXT "\"", cfg->img_mount_point, base, base);

  if (n < 0 || (size_t)n >= sizeof(opts)) {
    log_error("OverlayFS options too long");
    cleanup_volatile_overlay(cfg);
    return -1;
  }

  if (domount("overlay", merged, "overlay", 0, opts) < 0) {
    log_error("OverlayFS mount failed. Your kernel might not support it.");
    /* Cleanup: unmount tmpfs first, then remove workspace */
    umount2(base, MNT_DETACH);
    log_error("OverlayFS mount failed: %s", strerror(errno));
    cleanup_volatile_overlay(cfg);
    return -1;
  }

  /* 9. Update cfg->img_mount_point to the merged view */
  safe_strncpy(cfg->img_mount_point, merged, sizeof(cfg->img_mount_point));

  return 0;
}

/**
 * is_mount_in_namespace() - Check if `path` is mounted in OUR namespace.
 *
 * Reads /proc/self/mountinfo and searches for an exact match of `path`
 * in the mount-point column (field 5, 0-indexed: 4).
 *
 * Unlike is_mountpoint() (which uses stat-based device ID comparison),
 * this checks the kernel's mount table directly. This is critical for
 * overlay mounts that may share the same device as the lowerdir.
 *
 * Returns 1 if mounted, 0 if not.
 */
static bool is_mount_in_namespace(const char *path) {
  auto_fclose FILE *f = fopen("/proc/self/mountinfo", "r");
  if (!f)
    return false;

  char io_buf[65536];
  setvbuf(f, io_buf, _IOFBF, sizeof(io_buf));

  char line[4096];
  const size_t path_len = strlen(path);

  while (fgets(line, sizeof(line), f)) {
    /* mountinfo format: id parent_id major:minor root mount_point ... */
    /* We need field 5 (mount_point), skip first 4 fields */
    const char *p = line;
    for (int skip = 0; skip < 4 && *p; skip++) {
      while (*p && *p != ' ')
        p++;
      while (*p == ' ')
        p++;
    }
    /* p now points at the mount_point field */
    if (strncmp(p, path, path_len) == 0 &&
        (p[path_len] == ' ' || p[path_len] == '\n' || p[path_len] == '\0')) {
      return true;
    }
  }
  return false;
}

/**
 * cleanup_volatile_overlay() - Simplified OverlayFS cleanup.
 *
 * The overlay is mounted INSIDE the container's mount namespace (boot.c).
 * When the container dies, the kernel tears down the namespace and the
 * mounts vanish automatically.
 *
 * We simply check if the mount is visible in our namespace (host); if so,
 * we try to unmount it normally before deleting the workspace directory.
 */
int cleanup_volatile_overlay(cfg_t *cfg) {
  if (cfg->volatile_dir[0] == '\0')
    return 0;

  char merged[PATH_MAX + 32];
  snprintf(merged, sizeof(merged), "%s/merged", cfg->volatile_dir);

  /* Skip logging for clean exits - nothing prints after 'Powering off.' */

  /* 1. Fast path: check if mounts already vanished (normal case) */
  if (!is_mount_in_namespace(merged) &&
      !is_mount_in_namespace(cfg->volatile_dir)) {
    goto done;
  }

  /* 2. Slow path: unmount visible mounts (e.g. stop-rootfs on live container)
   */
  sync();
  umount(merged);
  umount(cfg->volatile_dir);

done:
  /* settle time for kernel to release backing store info */
  usleep(RETRY_DELAY_US / 2);
  const int r = remove_recursive(cfg->volatile_dir);
  cfg->volatile_dir[0] = '\0';
  return r;
}

void setup_custom_binds(cfg_t *cfg, const char *rootfs) {
  if (cfg->bind_count == 0 || !cfg->binds)
    return;

  /* Ensure mounts are processed in alphabetical order of destination
   * so parent directories are always mounted before children. */
  sort_bind_mounts(cfg);

  for (int i = 0; i < cfg->bind_count; i++) {
    char tgt[PATH_MAX * 2];
    const int n = snprintf(tgt, sizeof(tgt), "%s%s", rootfs, cfg->binds[i].dest);
    if (n < 0 || (size_t)n >= sizeof(tgt)) {
      log_warn("Bind mount target path too long, skipping: %s",
               cfg->binds[i].dest);
      continue;
    }

    /* Ensure parent directory exists.
     * Reject paths containing symlinks: an untrusted rootfs could contain
     * symlinks (e.g. mnt/hack -> /root) that redirect mkdir to host paths. */
    char parent[PATH_MAX];
    safe_strncpy(parent, tgt, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (slash) {
      *slash = '\0';
      if (path_has_symlink(parent)) {
        log_error("Security Violation: symlink in bind target path %s", parent);
        continue;
      }
      mkdir_p(parent, 0755);
    }

    /* Perform bind mount (handles source/target symlink checks securely) */
    if (bind_mount(cfg->binds[i].src, tgt) < 0) {
      log_warn("Failed to bind mount %s on %s (skipping)", cfg->binds[i].src,
               tgt);
      continue;
    }

    /* Verify isolation: Ensure we didn't accidentally mount over a host path
     * if the container rootfs had a complex malicious structure. */
    if (!is_subpath(rootfs, tgt)) {
      log_error("Security Violation: Bind destination %s escapes rootfs %s!",
                tgt, rootfs);
      umount2(tgt, MNT_DETACH);
      continue;
    }

    /* Remount RO if requested (bind always lands RW first) */
    if (cfg->binds[i].ro) {
      if (mount(nullptr, tgt, nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) < 0)
        log_warn("Failed to remount %s read-only: %s", tgt, strerror(errno));
    }
  }
}

/* ---------------------------------------------------------------------------
 * Rootfs Image Handling - Pure C loop device management (no host tools)
 * ---------------------------------------------------------------------------*/

int mount_rootfs_img(const char *img_path, char *mount_point, const size_t mp_size,
                     const char *name) {
  if (find_available_mountpoint(name, mount_point, mp_size) < 0) {
    log_error("Failed to find available mount point for %s", name);
    return -1;
  }

  /* Detect filesystem type from superblock magic */
  const char *fstype = detect_fs_type(img_path);
  if (!fstype) {
    log_warn("Unknown filesystem in %s. Only ext4 and btrfs are supported.",
             img_path);
    return -1;
  }

  /* Settle time: prevent "device busy" on rapid restarts */
  sync();
  usleep(RETRY_DELAY_US);

  /*
   * Build mount flags: base VFS flags + any fstype-specific extras.
   * pivot_root requires a writable mount to create .old_root, so no MS_RDONLY.
   */
  constexpr unsigned long mnt_flags = MS_NOATIME | MS_NODIRATIME;
  const char *mnt_data = nullptr;

  if (strcmp(fstype, "ext4") == 0) {
    mnt_data = "nodelalloc,errors=remount-ro,init_itable=0";
  } else if (strcmp(fstype, "btrfs") == 0) {
    /* btrfs defaults are usually sane */
    mnt_data = nullptr;
  }

  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt == 0)
      log_info("Mounting %s rootfs image %s on %s...", fstype, img_path,
               mount_point);
    else
      log_info("Mounting %s rootfs image %s on %s (Attempt %d/3)...", fstype,
               img_path, mount_point, attempt + 1);

    struct stat st;
    const bool is_blk = stat(img_path, &st) == 0 && S_ISBLK(st.st_mode);
    char final_src[PATH_MAX];
    auto_close int loop_fd = -1;

    if (is_blk) {
      safe_strncpy(final_src, img_path, sizeof(final_src));
    } else {
      loop_fd = loop_attach(img_path, final_src, sizeof(final_src));
      if (loop_fd < 0)
        goto retry;
    }

    const int ret = mount(final_src, mount_point, fstype, mnt_flags, mnt_data);
    /* AUTOCLEAR handles cleanup if mount failed */

    if (ret == 0) {
      /* Android FIX: Some kernels enforce nosuid/nodev on all loop mounts
       * if the backing file is on /data. Explicitly remount to clear them. */
      mount(nullptr, mount_point, nullptr, MS_REMOUNT | mnt_flags, mnt_data);
      return 0;
    }

    /* mount() failed: explicitly detach since AUTOCLEAR needs last-fd-close
     * + no active mounts to trigger; we already closed loop_fd so it should
     * auto-clear, but be explicit for kernels < 3.10 edge cases. */
    if (loop_fd >= 0)
      loop_detach(final_src);
    log_warn("mount(%s, %s) failed: %s", final_src, fstype, strerror(errno));

  retry:
    if (attempt < 2) {
      log_info("Retrying in 1s...");
      sync();
      usleep(RETRY_DELAY_US * 5);
    }
  }

  log_error("Failed to mount image %s after 3 attempts", img_path);
  return -1;
}

void unmount_rootfs_img(const char *mount_point, const bool silent) {
  if (!mount_point || !mount_point[0])
    return;

  /* Grab the backing loop device before we unmount (it disappears after) */
  char loop_dev[256] = {0};
  get_backing_dev(mount_point, loop_dev, sizeof(loop_dev));

  /* 1. Lazy unmount: detaches the mount even if files are open */
  sync();
  umount2(mount_point, MNT_DETACH);

  /* 2. Explicitly detach loop device (AUTOCLEAR also handles this, but be safe)
   */
  if (loop_dev[0])
    loop_detach(loop_dev);

  /* 3. Settle and force if still mounted (stubborn old kernels) */
  sync();
  usleep(RETRY_DELAY_US);
  if (is_mountpoint(mount_point)) {
    umount2(mount_point, MNT_DETACH | MNT_FORCE);
    usleep(RETRY_DELAY_US / 2);
  }

  /* 4. Cleanup and log */
  const bool still_mounted = is_mountpoint(mount_point);
  if (rmdir(mount_point) == 0 || !still_mounted) {
    if (!silent)
      log_info("Unmounted rootfs image from %s.", mount_point);
  } else if (errno != ENOENT) {
    if (!silent)
      log_warn("Cleanup warning: %s is still busy/mounted.", mount_point);
  }
}
