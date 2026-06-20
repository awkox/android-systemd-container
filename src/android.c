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
