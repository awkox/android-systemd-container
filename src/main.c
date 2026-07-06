#include "asc.h"

/*
 * !!!我们假设本程序在除了系统关机外不会被意外杀死!!!
 * !!!所以我们移除了部分意外防护代码，仅保留了正常情况的处理!!!
 * !!!若程序意外退出，必须重启系统进行清理!!!
 */

static void print_usage(void) {
  printf(
      "Usage: " PROJECT_NAME " [options] <command> [args]\n\n"
      "Commands:\n"
      "  start                     Start a new container\n"
      "  stop                      Stop one or more containers\n"
      "  restart                   Restart a container\n"
      "  info                      Show detailed container info\n"
      "  pid                       Show the live PID of the container init\n"
      "  show                      List all running containers\n"
      "  check                     Check system requirements\n"
      "  help                      Show this help message\n"
      "  daemon                    Run daemon mode (use --foreground for "
      "foreground execution)\n"
      "  daemon-stop               Stop the running background daemon\n\n"

      "Options (Container Setup):\n"
      "  -n, --name=NAME           Container name (mandatory)\n"
      "  -C, --conf=PATH           Load configuration from file\n\n"

      "Options (Runtime):\n"
      "  -f, --foreground          Run in foreground (attach console)\n"
      "      --format              Machine-parseable output (KEY=VALUE)\n"
      "      --help                Show this help message\n\n");
}

/**
 * CLI-level configuration validation with professional error reporting.
 * Deters configuration errors early before entering the runtime.
 */
static int validate_configuration_cli(cfg_t *cfg) {
  bool error = false;

  if (!cfg->conf.container_name[0]) {
    log_error("Container name is mandatory (--name).");
    error = true;
  } else if (reject_container_name(cfg->conf.container_name) < 0) {
    error = true;
  }

  if (!cfg->conf.rootfs_img_path[0]) {
    log_error("No rootfs image specified in configuration.");
    error = true;
  }

  /* Existence checks */
  if (cfg->conf.rootfs_img_path[0] && access(cfg->conf.rootfs_img_path, F_OK) != 0) {
    log_error("Rootfs image not found: '%s' (%s)", cfg->conf.rootfs_img_path,
              strerror(errno));
    error = true;
  }

  /* Image mode requires a name for the mount point */
  if (cfg->conf.rootfs_img_path[0] && !cfg->conf.container_name[0]) {
    log_error("Rootfs image requires a container name (--name).");
    error = true;
  }

  if (cfg->conf.custom_init[0]) {
    if (cfg->conf.custom_init[0] != '/') {
      log_error("Custom init path must be absolute: %s", cfg->conf.custom_init);
      error = true;
    } else if (strchr(cfg->conf.custom_init, ' ')) {
      log_error("Custom init path cannot contain spaces: %s", cfg->conf.custom_init);
      error = true;
    }
  }

  return error ? -1 : 0;
}

int main(const int argc, char **argv) {
  int ret = 0;
  /* CRITICAL: Zero all fields to avoid garbage pointer in dynamic arrays */
  cfg_t cfg = {};

  static const struct option long_options[] = {
    {"name", required_argument, nullptr, 'n'},
    {"foreground", no_argument, nullptr, 'f'},
    {"config", required_argument, nullptr, 'C'},
    {"format", no_argument, nullptr, 265},
    {"help", no_argument, nullptr, 270},
    {nullptr, 0, nullptr, 0}
  };

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
  const char *discovered_cmd = nullptr;
  constexpr char temp_i[PATH_MAX] = "";
  int opt;

  /* 1. Discovery Pass: Capture identity and command without permuting argv.
   * Using '-' at the start of optstring returns non-options as '1'. */
  while ((opt = getopt_long(argc, argv, "-n:fC:", long_options, nullptr)) != -1) {
    if (opt == 1) { /* Non-option argument */
      if (!discovered_cmd) {
        discovered_cmd = optarg;
      }
    } else if (opt == 'C') {
      safe_strncpy(cfg.rt.config_file, optarg, sizeof(cfg.rt.config_file));
    } else if (opt == 'n') {
      if (reject_container_name(optarg) < 0) {
        ret = 1;
        goto cleanup;
      }
      safe_strncpy(cfg.conf.container_name, optarg, sizeof(cfg.conf.container_name));
    }
  }
  optind = 0; /* Reset for next steps */

  /*
   * Daemon Proxying:
   * Optimistically attempt to proxy commands to the background daemon.
   * If the daemon is not reachable, fall back to direct execution.
   */
  const bool is_daemon_cmd = discovered_cmd && strcmp(discovered_cmd, "daemon") == 0;

  /*
   * Commands that do not require root access (help, version) or
   * must be run locally to avoid recursive loops (mode) are never proxied.
   */
  const bool is_no_root_cmd =
      discovered_cmd && (strcmp(discovered_cmd, "help") == 0 ||
                         strcmp(discovered_cmd, "mode") == 0 ||
                         strcmp(discovered_cmd, "check") == 0);

  if (!is_daemon_cmd && !is_no_root_cmd && getenv("NO_PROXY") == nullptr) {
    const int proxy_ret = client_run(argc - 1, argv + 1);
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
   * 4. 如果配置尚未成功加载，执行恢复扫描以尝试从
   *    <workspace dir>/config/<name>/container.config 加载。
   */
  const bool is_stateful =
      discovered_cmd && (strcmp(discovered_cmd, "stop") == 0 ||
                         strcmp(discovered_cmd, "restart") == 0 ||
                         strcmp(discovered_cmd, "pid") == 0 ||
                         strcmp(discovered_cmd, "info") == 0);

  bool loaded = false;
  if (cfg.rt.config_file[0]) {
    if (config_load(cfg.rt.config_file, &cfg) < 0) {
      log_error("Failed to load configuration from '%s': %s", cfg.rt.config_file,
                strerror(errno));
      ret = 1;
      goto cleanup;
    }
    loaded = true;
  } else {
    auto_free char *auto_p = config_auto_path(temp_i);
    if (auto_p) {
      safe_strncpy(cfg.rt.config_file, auto_p, sizeof(cfg.rt.config_file));
      if (config_load(cfg.rt.config_file, &cfg) == 0) {
        loaded = true;
      } else if (errno != ENOENT) {
        log_warn("Failed to load auto-detected config from '%s': %s",
                 cfg.rt.config_file, strerror(errno));
      }
    }
  }

  /* For stateful commands, we absolutely need a container name.
   * If we don't have one by now, try to guess the active container. */
  if (is_stateful && cfg.conf.container_name[0] == '\0') {
    log_error("Container name is required for this command.");
    log_info("Please specify the container using '-n' or '--name'.");
    ret = 1;
    goto cleanup;
  }

  /* If we have a name but haven't successfully loaded a config file yet, load
   * by name. */
  if (!loaded && cfg.conf.container_name[0] != '\0') {
    if (config_load_by_name(cfg.conf.container_name, &cfg) < 0) {
      /* If loading by name fails and it's a stateful command, maybe the
       * container was moved or renamed. Perform a recovery scan of running
       * systems as a last resort. */
      if (is_stateful) {
        if (config_load_by_name(cfg.conf.container_name, &cfg) < 0) {
          log_error("Container '%s' not found or metadata missing.",
                    cfg.conf.container_name);
          ret = 1;
          goto cleanup;
        }
      }
    }
  }

  /* Apply configuration reset immediately AFTER disk load, BEFORE CLI overrides
   */

  const char *optstring = "n:fC:";

  while ((opt = getopt_long(argc, argv, optstring, long_options, nullptr)) != -1) {
    switch (opt) {
    case 'n':
      if (reject_container_name(optarg) < 0) {
        ret = 1;
        goto cleanup;
      }
      safe_strncpy(cfg.conf.container_name, optarg, sizeof(cfg.conf.container_name));
      break;
    case 'f':
      cfg.rt.foreground = 1;
      break;
    case 'C':
      safe_strncpy(cfg.rt.config_file, optarg, sizeof(cfg.rt.config_file));
      break;
    case 265:
      /* --format: machine-parseable output */
      cfg.rt.format_output = true;
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
    log_error("Missing command");
    log_info("Run '%s help' for usage information.", argv[0]);
    ret = 1;
    goto cleanup;
  }

  const char *cmd = argv[optind];

  /* Set up global logging context for centralized logging engine */
  if (cfg.conf.container_name[0] != '\0') {
    safe_strncpy(log_container_name, cfg.conf.container_name,
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

  /* start/restart: single container only */
  if (strcmp(cmd, "start") == 0) {
    if (validate_configuration_cli(&cfg) < 0) {
      ret = 1;
      goto cleanup;
    }
    if (check_requirements_hw(cfg.conf.hw_access) < 0) {
      ret = 1;
      goto cleanup;
    }
    print_privileged_warning(cfg.conf.privileged_mask);
    if (cfg.conf.privileged_mask & PRIV_NOSEC && cfg.conf.block_nested_ns)
      log_warn("--privileged=noseccomp is active: --block-nested-namespaces "
               "is now a NO-OP.");
    cgroup_host_bootstrap(cfg.conf.force_cgroupv1);
    if (cfg.conf.container_name[0] == '\0' && cfg.conf.rootfs_img_path[0])
      generate_container_name(cfg.conf.rootfs_img_path, cfg.conf.container_name,
                              sizeof(cfg.conf.container_name));
    ret = start_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "stop") == 0) {
    ret = stop_rootfs(&cfg, false);
    goto cleanup;
  }

  if (strcmp(cmd, "restart") == 0) {
    if (check_requirements_hw(cfg.conf.hw_access) < 0) {
      ret = 1;
      goto cleanup;
    }
    print_privileged_warning(cfg.conf.privileged_mask);
    if (cfg.conf.privileged_mask & PRIV_NOSEC && cfg.conf.block_nested_ns)
      log_warn("--privileged=noseccomp is active: --block-nested-namespaces "
               "is now a NO-OP.");
    cgroup_host_bootstrap(cfg.conf.force_cgroupv1);
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
    ret = show_info(&cfg, false);
    goto cleanup;
  }

  if (strcmp(cmd, "daemon") == 0) {
    ret = daemon_run(cfg.rt.foreground);
    goto cleanup;
  }

  /* 如果执行到这里，说明 Daemon 没启动（client_run 代理失败并回退了） */
  if (strcmp(cmd, "daemon-stop") == 0) {
    log_info("Daemon is not running.");
    ret = 0;
    goto cleanup;
  }

  log_error("Unknown command: '%s'", cmd);
  log_info("Run '%s help' for usage information.", argv[0]);
  ret = 1;

cleanup:
  return ret;
}
