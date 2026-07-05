/*
 * ds-fork v6 - Hardware Access Module
 *
 * This module manages GPU acceleration and hardware device nodes. To keep your
 * system stable, we exclusively use "render nodes" (/dev/dri/renderD*) for GPU
 * access.
 *
 * Why? Because render nodes allow multiple processes (like ds-fork and your
 * host's X11/Wayland) to share the GPU safely. "Card nodes" (/dev/dri/card*)
 * are avoided because they require exclusive control (DRM master), and trying
 * to share them often leads to driver hangs or kernel panics on desktop Linux.
 *
 * This approach gives you full OpenGL, Vulkan, and video acceleration while
 * ensuring your host system stays rock solid. It's the same industry standard
 * used by major container projects like Docker and Podman.
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

