/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

/* ---------------------------------------------------------------------------
 * Android detection
 * ---------------------------------------------------------------------------*/

int is_android(void) {
  static int cached_result = -1;
  if (cached_result != -1)
    return cached_result;

  /* Priority 1: Check for recovery environment (e.g., TWRP) */
  if (access("/system/bin/recovery", F_OK) == 0) {
    cached_result = 0;
  }
  /* Priority 2: Check for core Android system markers */
  else if (access("/system/build.prop", F_OK) == 0 ||
           access("/system/bin/app_process", F_OK) == 0) {
    cached_result = 1;
  }
  /* Fallback: Not a standard Android environment */
  else {
    cached_result = 0;
  }

  return cached_result;
}

/* ---------------------------------------------------------------------------
 * Storage
 * ---------------------------------------------------------------------------*/

int android_setup_storage(const char *rootfs_path) {
  if (!is_android()) {
    return 0;
  }

  if (!rootfs_path) {
    log_warn("android_setup_storage called with NULL rootfs_path");
    return -1;
  }

  const char *storage_src = "/storage/emulated/0";
  struct stat st;

  if (stat(storage_src, &st) < 0 || !S_ISDIR(st.st_mode) ||
      access(storage_src, R_OK) < 0) {
    log_warn("Android storage not found or not readable at %s", storage_src);
    return -1;
  }

  /* Create target directories inside rootfs: storage/, storage/emulated/,
   * storage/emulated/0 */
  char path[PATH_MAX];
  int ret;

  ret = snprintf(path, sizeof(path), "%s/storage", rootfs_path);
  if (ret < 0 || (size_t)ret >= sizeof(path))
    return -1;
  if (mkdir(path, 0755) < 0 && errno != EEXIST)
    return -1;

  ret = snprintf(path, sizeof(path), "%s/storage/emulated", rootfs_path);
  if (ret < 0 || (size_t)ret >= sizeof(path))
    return -1;
  if (mkdir(path, 0755) < 0 && errno != EEXIST)
    return -1;

  ret = snprintf(path, sizeof(path), "%s/storage/emulated/0", rootfs_path);
  if (ret < 0 || (size_t)ret >= sizeof(path))
    return -1;
  if (mkdir(path, 0755) < 0 && errno != EEXIST)
    return -1;

  log_info("Mounting Android internal storage to /storage/emulated/0...");
  if (mount(storage_src, path, NULL, MS_BIND | MS_REC, NULL) < 0) {
    log_warn("Failed to bind-mount Android storage %s -> %s: %s", storage_src,
             path, strerror(errno));
    return -1;
  }

  return 0;
}
