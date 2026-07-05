#include "asc.h"

/* Universal drops - even in hardware mode, there's no legitimate use
 * for CAP_SYS_MODULE inside a container (kernel module loading).
 * CAP_SYS_BOOT is intentionally preserved - it is required for in-container
 * reboot(2) to work inside a PID namespace without rebooting the host.
 * CAP_MKNOD is intentionally PRESERVED: nested container runtimes
 * (Docker-in-Docker, LXC-in-LXC) need mknod to create /dev nodes for
 * their own containers.  /proc/partitions is nullified in the jail mask
 * to prevent host block-device enumeration. */
const int universal_drops[] = {
  CAP_SYS_MODULE,
  -1,
};

/* Standard Hardening Tier: drop capabilities that affect host stability
 * or allow escaping the container's isolation. */
const int caps_to_drop[] = {
  CAP_SYS_RAWIO,       /* Raw hardware access (I/O ports, memory) */
  CAP_SYS_PTRACE,      /* Process tracing/injection across namespaces */
  CAP_SYS_PACCT,       /* Process accounting */
  CAP_SYSLOG,          /* log */
  CAP_MAC_ADMIN,       /* Mandatory Access Control policy modification */
  CAP_MAC_OVERRIDE,    /* Bypass MAC policies */
  CAP_WAKE_ALARM,      /* Affect host power management / wakeups */
  CAP_BLOCK_SUSPEND,   /* Affect host power management / sleep */
  CAP_AUDIT_READ,      /* Read kernel audit logs */
  CAP_DAC_READ_SEARCH, /* Bypass file read/directory search permissions -
                        * the other half of the Shocker escape: combined
                        * with open_by_handle_at it allows reading any
                        * file on the host outside the mount namespace. */
  -1,
};

/*
 * apply_capability_hardening()
 *
 * Drops dangerous capabilities from the bounding set to reduce the container's
 * attack surface.
 *
 * In Standard Mode (hw_access=0), we drop several sensitive capabilities.
 * In Hardware Mode (hw_access=1), we preserve most to ensure full
 * low-level hardware access (USB, Serial, Bluetooth, Flashing).
 */
void apply_capability_hardening(bool hw_access, int privileged_mask) {
  int total_dropped = 0;

  if (privileged_mask & PRIV_NOCAPS) {
    log_info("[SEC] --privileged=nocaps: skipping capability drops.");
    return;
  }

  for (int i = 0; universal_drops[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, universal_drops[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] Failed to drop universal cap %d: %s",
                 universal_drops[i], strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  if (hw_access) {
    log_info(
        "[SEC] Hardware Mode: preserved bounding set (dropped %d universal "
        "caps).",
        total_dropped);
    return;
  }

  for (int i = 0; caps_to_drop[i] != -1; i++) {
    if (prctl(PR_CAPBSET_DROP, caps_to_drop[i], 0, 0, 0) < 0) {
      if (errno != EINVAL) {
        log_warn("[SEC] Failed to drop cap %d: %s", caps_to_drop[i],
                 strerror(errno));
      }
    } else {
      total_dropped++;
    }
  }

  log_info("[SEC] Bounding set hardened (dropped %d caps).", total_dropped);
}