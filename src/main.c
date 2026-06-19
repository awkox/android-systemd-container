/*
 * ds-fork v6 - High-performance Container Runtime
 *
 * Copyright (C) 2026 ravindu644 <droidcasts@protonmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "asc.h"

int log_silent = 0;
char log_container_name[256] = "";
int log_container_fd = -1;

/* ---------------------------------------------------------------------------
 * Usage / Help
 * ---------------------------------------------------------------------------*/

void print_usage(void) {
  printf(
      "Usage: " PROJECT_NAME " [options] <command> [args]\n\n" C_BOLD
      "Commands:" C_RESET "\n"
      "  start                     Start a new container\n"
      "  stop                      Stop one or more containers\n"
      "  restart                   Restart a container\n"
      "  usage                     Show container uptime, CPU and RAM usage\n"
      "  info                      Show detailed container info\n"
      "  pid                       Show the live PID of the container init\n"
      "  show                      List all running containers\n"
      "  scan                      Scan for untracked containers\n"
      "  check                     Check system requirements\n"
      "  help                      Show this help message\n"
      "  daemon                    Run daemon mode (use --foreground for "
      "foreground execution)\n\n"

      C_BOLD "Options (Container Setup):" C_RESET "\n"
      "  -n, --name=NAME           Container name (mandatory)\n"
      "  -C, --conf=PATH           Load configuration from file\n\n"

      C_BOLD "Options (Runtime):" C_RESET "\n"
      "  -f, --foreground          Run in foreground (attach console)\n"
      "      --format              Machine-parseable output (KEY=VALUE)\n"
      "      --help                Show this help message\n\n");
}

/* ---------------------------------------------------------------------------
 * Validation Helpers
 * ---------------------------------------------------------------------------*/

static int validate_kernel_version(void) {
  int major = 0, minor = 0;
  if (get_kernel_version(&major, &minor) < 0) {
    log_error("Failed to detect kernel version.");
    return -1;
  }

  if (major < MIN_KERNEL_MAJOR ||
      (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)) {
    printf("\n" C_RED C_BOLD "[ FATAL: UNSUPPORTED KERNEL ]" C_RESET "\n\n");
    log_error(PROJECT_NAME " requires at least Linux %d.%d.0.",
              MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR);
    log_info("Detected kernel: %d.%d", major, minor);
    return -1;
  }

  return 0;
}

/**
 * CLI-level configuration validation with professional error reporting.
 * Deters configuration errors early before entering the runtime.
 */
static int validate_configuration_cli(struct config *cfg) {
  int errors = 0;

  if (!cfg->container_name[0]) {
    log_error("Container name is mandatory (--name).");
    errors++;
  } else if (reject_container_name(cfg->container_name) < 0) {
    errors++;
  }

  if (!cfg->rootfs_img_path[0]) {
    log_error("No rootfs image specified in configuration.");
    errors++;
  }

  /* Existence checks */
  if (cfg->rootfs_img_path[0] && access(cfg->rootfs_img_path, F_OK) != 0) {
    log_error("Rootfs image not found: '%s' (%s)", cfg->rootfs_img_path,
              strerror(errno));
    errors++;
  }

  /* Image mode requires a name for the mount point */
  if (cfg->rootfs_img_path[0] && !cfg->container_name[0]) {
    log_error("Rootfs image requires a container name (--name).");
    errors++;
  }

  if (cfg->custom_init[0]) {
    if (cfg->custom_init[0] != '/') {
      log_error("Custom init path must be absolute: %s", cfg->custom_init);
      errors++;
    } else if (strchr(cfg->custom_init, ' ')) {
      log_error("Custom init path cannot contain spaces: %s", cfg->custom_init);
      errors++;
    }
  }

  return (errors > 0) ? -1 : 0;
}

static int auto_resolve_container_name(struct config *cfg) {
  if (cfg->container_name[0] != '\0')
    return 0;

  char first_name[256];
  int count = count_running_containers(first_name, sizeof(first_name));

  /* If 0 containers found, try a scan once if we aren't already silent
   * (prevents infinite scan loops) */
  if (count == 0 && !log_silent) {
    log_silent = 1;
    scan_containers();
    log_silent = 0;
    count = count_running_containers(first_name, sizeof(first_name));
  }

  /* If still not found after scan, fail */
  if (count == 0) {
    log_error("No containers are currently running.");
    return -1;
  }

  if (count > 1) {
    log_error("Multiple containers running. Please specify " C_BOLD
              "--name" C_RESET ".");
    show_containers(cfg);
    return -1;
  }

  safe_strncpy(cfg->container_name, first_name, sizeof(cfg->container_name));
  return 0;
}

/* ---------------------------------------------------------------------------
 * Command Dispatch
 * ---------------------------------------------------------------------------*/

static void check_network_namespace(struct config *cfg) {
  if (cfg->net_mode != NET_HOST) {
    if (!check_ns(CLONE_NEWNET, "net")) {
      printf("\n" C_RED C_BOLD
             "[ FATAL: NETWORK NAMESPACE UNSUPPORTED ]" C_RESET "\n\n");
      log_error("Kernel does not support CLONE_NEWNET (network namespaces).");
      log_info("Cannot use --net=none.");
      log_info("Tip: Use --net=host (default) for shared host networking.");
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char **argv) {
  int ret = 0;
  struct config cfg;
  char raw_names[4096] = "";
  /* CRITICAL: Zero all fields to avoid garbage pointer in dynamic arrays */
  memset(&cfg, 0, sizeof(cfg));

  safe_strncpy(cfg.prog_name, argv[0], sizeof(cfg.prog_name));

  static struct option long_options[] = {
      {"name", required_argument, 0, 'n'},
      {"foreground", no_argument, 0, 'f'},
      {"config", required_argument, 0, 'C'},
      {"format", no_argument, 0, 265},
      {"help", no_argument, 0, 270},
      {0, 0, 0, 0}};

  extern int opterr;
  opterr = 0;

  /* Resolve relative path arguments to absolute before any parsing.
   * The daemon runs from CWD='/' (daemonize calls chdir("/")), so a relative
   * path like --conf=./file.conf would resolve against '/' in the re-exec'd
   * child.  Doing this here - while we still own the user's CWD - means every
   * subsequent getopt pass reads absolute paths, covering all execution modes.
   */
  resolve_argv_paths(argc - 1, argv + 1);

  /*
   * Multi-pass argument parsing:
   * 1. Discovery Pass: Find command and identity (name/rootfs/conf) anywhere.
   * 2. Load config.
   * 3. Override Pass: Apply CLI overrides on top of loaded config.
   */
  const char *discovered_cmd = NULL;
  char temp_i[PATH_MAX] = {0};
  int opt;

  /* 1. Discovery Pass: Capture identity and command without permuting argv.
   * Using '-' at the start of optstring returns non-options as '1'. */
  while ((opt = getopt_long(argc, argv, "-n:fC:", long_options,
                            NULL)) != -1) {
    if (opt == 1) { /* Non-option argument */
      if (!discovered_cmd) {
        discovered_cmd = optarg;
      }
    } else if (opt == 'C') {
      safe_strncpy(cfg.config_file, optarg, sizeof(cfg.config_file));
      cfg.config_file_specified = 1;
    } else if (opt == 'n') {
      if (parse_and_validate_names(optarg, raw_names, sizeof(raw_names)) < 0) {
        ret = 1;
        goto cleanup;
      }
      safe_strncpy(cfg.container_name, optarg, sizeof(cfg.container_name));
    }
  }
  optind = 0; /* Reset for next steps */

  /*
   * Daemon Proxying:
   * Optimistically attempt to proxy commands to the background daemon.
   * If the daemon is not reachable, fall back to direct execution.
   */
  int is_daemon_cmd = (discovered_cmd && strcmp(discovered_cmd, "daemon") == 0);

  /*
   * Commands that do not require root access (help, version) or
   * must be run locally to avoid recursive loops (mode) are never proxied.
   */
  int is_no_root_cmd =
      (discovered_cmd && (strcmp(discovered_cmd, "help") == 0 ||
                          strcmp(discovered_cmd, "mode") == 0 ||
                          strcmp(discovered_cmd, "check") == 0));

  if (!is_daemon_cmd && !is_no_root_cmd && getenv("NO_PROXY") == NULL) {
    int proxy_ret = client_run(argc - 1, argv + 1);
    if (proxy_ret != -2) {
      ret = proxy_ret;
      goto cleanup;
    }
  }

  /* Unified root gate: block all non-exempt commands before any work begins */
  if (!is_no_root_cmd && getuid() != 0) {
    log_error("Root privileges required for '%s'",
              discovered_cmd ? discovered_cmd : "(unknown)");
    ret = 1;
    goto cleanup;
  }

  /*
   * Unified Configuration Discovery and Loading
   * 1. Try to load from explicitly provided config file.
   * 2. Otherwise try to auto-detect config from rootfs paths.
   * 3. Ensure we have a container name for stateful commands.
   * 4. Perform a recovery scan to load from
   *    <workspace dir>/Containers/<name>/container.config if config hasn't
   *    been loaded yet.
   */
  int is_stateful =
      (discovered_cmd && (strcmp(discovered_cmd, "stop") == 0 ||
                          strcmp(discovered_cmd, "restart") == 0 ||
                          strcmp(discovered_cmd, "pid") == 0 ||
                          strcmp(discovered_cmd, "info") == 0 ||
                          strcmp(discovered_cmd, "usage") == 0));

  int loaded = 0;
  if (cfg.config_file_specified) {
    if (config_load(cfg.config_file, &cfg) < 0) {
      log_error("Failed to load configuration from '%s': %s", cfg.config_file,
                strerror(errno));
      ret = 1;
      goto cleanup;
    }
    loaded = 1;
  } else {
    char *auto_p = config_auto_path(temp_i);
    if (auto_p) {
      safe_strncpy(cfg.config_file, auto_p, sizeof(cfg.config_file));
      if (config_load(cfg.config_file, &cfg) == 0) {
        loaded = 1;
      } else if (errno != ENOENT) {
        log_warn("Failed to load auto-detected config from '%s': %s",
                 cfg.config_file, strerror(errno));
      }
      free(auto_p);
    }
  }

  /* For stateful commands, we absolutely need a container name.
   * If we don't have one by now, try to guess the active container. */
  if (is_stateful && cfg.container_name[0] == '\0') {
    if (auto_resolve_container_name(&cfg) < 0) {
      ret = 1;
      goto cleanup;
    }
  }

  /* If we have a name but haven't successfully loaded a config file yet, load
   * by name. Skip for comma-separated names - multi_* handles those. */
  if (!loaded && cfg.container_name[0] != '\0' && !strchr(raw_names, ',')) {
    if (config_load_by_name(cfg.container_name, &cfg) < 0) {
      /* If loading by name fails and it's a stateful command, maybe the
       * container was moved or renamed. Perform a recovery scan of running
       * systems as a last resort. */
      if (is_stateful) {
        int prev = log_silent;
        log_silent = 1;
        scan_containers();
        log_silent = prev;

        if (config_load_by_name(cfg.container_name, &cfg) < 0) {
          log_error("Container '%s' not found or metadata missing.",
                    cfg.container_name);
          ret = 1;
          goto cleanup;
        }
      }
    }
  }

  /* Apply configuration reset immediately AFTER disk load, BEFORE CLI overrides
   */

  const char *optstring = "n:fC:";

  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
    case 'n':
      if (parse_and_validate_names(optarg, raw_names, sizeof(raw_names)) < 0) {
        ret = 1;
        goto cleanup;
      }
      safe_strncpy(cfg.container_name, optarg, sizeof(cfg.container_name));
      break;
    case 'f':
      cfg.foreground = 1;
      break;
    case 'C':
      safe_strncpy(cfg.config_file, optarg, sizeof(cfg.config_file));
      cfg.config_file_specified = 1;
      break;
    case 265:
      /* --format: machine-parseable output */
      cfg.format_output = 1;
      break;
    case 270: /* --help */
      print_usage();
      ret = 0;
      goto cleanup;
    default:
      break;
    }
  }

  if (optind >= argc) {
    log_error(C_BOLD "Missing command" C_RESET);
    log_info("Run '" C_BOLD "%s help" C_RESET "' for usage information.",
             cfg.prog_name);
    ret = 1;
    goto cleanup;
  }

  const char *cmd = argv[optind];

  /* Set up global logging context for centralized logging engine */
  if (cfg.container_name[0] != '\0') {
    safe_strncpy(log_container_name, cfg.container_name,
                 sizeof(log_container_name));
  }

  /* Basic info commands */
  if (strcmp(cmd, "check") == 0) {
    ret = check_requirements_detailed();
    goto cleanup;
  }
  if (strcmp(cmd, "help") == 0) {
    print_usage();
    ret = 0;
    goto cleanup;
  }

  if (strcmp(cmd, "mode") == 0) {
    printf("%s\n", daemon_probe() ? "daemon" : "direct");
    ret = 0;
    goto cleanup;
  }

  ensure_runtime();

  if (strcmp(cmd, "show") == 0) {
    ret = show_containers(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "scan") == 0) {
    scan_containers();
    ret = 0;
    goto cleanup;
  }

  /* start/restart: single container only */
  if (strcmp(cmd, "start") == 0) {
    if (strchr(raw_names, ',')) {
      log_error("start does not support multiple containers.");
      ret = 1;
      goto cleanup;
    }
    if (validate_configuration_cli(&cfg) < 0) {
      ret = 1;
      goto cleanup;
    }
    if (validate_kernel_version() < 0) {
      ret = 1;
      goto cleanup;
    }
    if (check_requirements_hw(cfg.hw_access) < 0) {
      ret = 1;
      goto cleanup;
    }
    check_network_namespace(&cfg);
    print_privileged_warning(cfg.privileged_mask);
    if ((cfg.privileged_mask & PRIV_NOSEC) && cfg.block_nested_ns)
      log_warn("--privileged=noseccomp is active: --block-nested-namespaces "
               "is now a NO-OP.");
    cgroup_host_bootstrap(cfg.force_cgroupv1);
    if (cfg.container_name[0] == '\0' && cfg.rootfs_img_path[0])
      generate_container_name(cfg.rootfs_img_path, cfg.container_name,
                              sizeof(cfg.container_name));
    ret = start_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "stop") == 0) {
    ret = strchr(raw_names, ',') ? multi_stop(raw_names) : stop_rootfs(&cfg, 0);
    goto cleanup;
  }

  if (strcmp(cmd, "restart") == 0) {
    if (strchr(raw_names, ',')) {
      log_error("restart does not support multiple containers.");
      ret = 1;
      goto cleanup;
    }
    if (check_requirements_hw(cfg.hw_access) < 0) {
      ret = 1;
      goto cleanup;
    }
    check_network_namespace(&cfg);
    print_privileged_warning(cfg.privileged_mask);
    if ((cfg.privileged_mask & PRIV_NOSEC) && cfg.block_nested_ns)
      log_warn("--privileged=noseccomp is active: --block-nested-namespaces "
               "is now a NO-OP.");
    cgroup_host_bootstrap(cfg.force_cgroupv1);
    ret = restart_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "pid") == 0) {
    pid_t pid = 0;
    if (is_container_running(&cfg, &pid) && pid > 0) {
      printf("%d\n", (int)pid);
      ret = 0;
    } else {
      printf("NONE\n");
      ret = 1;
    }
    goto cleanup;
  }

  if (strcmp(cmd, "info") == 0) {
    ret = show_info(&cfg, 0);
    goto cleanup;
  }

  if (strcmp(cmd, "usage") == 0) {
    ret = show_container_usage(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "daemon") == 0) {
    ret = daemon_run(cfg.foreground);
    goto cleanup;
  }

  log_error("Unknown command: '%s'", cmd);
  log_info("Run '" C_BOLD "%s help" C_RESET "' for usage information.",
           cfg.prog_name);
  ret = 1;

cleanup:
  config_free(&cfg);
  return ret;
}
