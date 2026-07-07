#include "asc.h"

/*
 * !!!我们假设本程序在除了系统关机外不会被意外杀死!!!
 * !!!所以我们移除了部分意外防护代码，仅保留了正常情况的处理!!!
 * !!!若程序意外退出，必须重启系统进行清理!!!
 */

static void print_usage(void) {
  printf(
      "Usage: " PROJECT_NAME " <command> [args]\n\n"
      "Commands:\n"
      "  daemon start [-f]         Start the background daemon (-f for foreground)\n"
      "  daemon stop               Stop the running background daemon\n"
      "  start NAME [CONFIG] [-f]  Start container NAME with optional CONFIG file\n"
      "  stop NAME                 Stop container NAME\n"
      "  info NAME                 Show detailed container info\n"
      "  check                     Check system requirements\n"
      "  help                      Show this help message\n\n");
}

/**
 * CLI-level configuration validation with professional error reporting.
 * Deters configuration errors early before entering the runtime.
 */
static int validate_configuration_cli(asc_conf_t *conf) {
  bool error = false;

  if (!conf->container_name[0]) {
    log_error("Container name is mandatory.");
    error = true;
  } else if (reject_container_name(conf->container_name) < 0) {
    error = true;
  }

  if (!conf->rootfs_img_path[0]) {
    log_error("No rootfs image specified in configuration.");
    error = true;
  }

  /* Existence checks */
  if (conf->rootfs_img_path[0] && access(conf->rootfs_img_path, F_OK) != 0) {
    log_error("Rootfs image not found: '%s' (%s)", conf->rootfs_img_path,
              strerror(errno));
    error = true;
  }

  /* Image mode requires a name for the mount point */
  if (conf->rootfs_img_path[0] && !conf->container_name[0]) {
    log_error("Rootfs image requires a container name.");
    error = true;
  }

  if (conf->custom_init[0]) {
    if (conf->custom_init[0] != '/') {
      log_error("Custom init path must be absolute: %s", conf->custom_init);
      error = true;
    } else if (strchr(conf->custom_init, ' ')) {
      log_error("Custom init path cannot contain spaces: %s", conf->custom_init);
      error = true;
    }
  }

  return error ? -1 : 0;
}

int main(const int argc, char **argv) {
  int ret = 0;
  /* CRITICAL: Zero all fields to avoid garbage pointer in dynamic arrays */
  cfg_t cfg = {};

  if (argc < 2) {
    print_usage();
    return 1;
  }

  /* Resolve relative path arguments to absolute before any parsing.
   * The daemon runs from CWD='/' (daemonize calls chdir("/")), so a relative
   * path would resolve against '/' in the re-exec'd child.
   */
  resolve_argv_paths(argc - 1, argv + 1);

  const char *cmd = argv[1];
  const char *subcmd = nullptr;
  const char *name = nullptr;
  const char *config_path = nullptr;
  bool foreground = false;
  bool is_daemon_cmd = false;
  bool is_no_root_cmd = false;
  bool is_stateful = false;

  /* Strict CLI matching */
  if (strcmp(cmd, "daemon") == 0) {
    is_daemon_cmd = true;
    if (argc < 3) goto usage_error;
    subcmd = argv[2];
    if (strcmp(subcmd, "start") == 0) {
      if (argc == 4) {
        if (strcmp(argv[3], "-f") == 0) foreground = true;
        else goto usage_error;
      } else if (argc > 4) {
        goto usage_error;
      }
    } else if (strcmp(subcmd, "stop") == 0) {
      if (argc > 3) goto usage_error;
    } else {
      goto usage_error;
    }
  } else if (strcmp(cmd, "start") == 0) {
    if (argc < 3 || argc > 5) goto usage_error;
    name = argv[2];
    if (argc == 4) {
      if (strcmp(argv[3], "-f") == 0) {
        foreground = true;
      } else {
        config_path = argv[3];
      }
    } else if (argc == 5) {
      config_path = argv[3];
      if (strcmp(argv[4], "-f") == 0) {
        foreground = true;
      } else {
        goto usage_error;
      }
    }
  } else if (strcmp(cmd, "stop") == 0) {
    if (argc != 3) goto usage_error;
    name = argv[2];
    is_stateful = true;
  } else if (strcmp(cmd, "info") == 0) {
    if (argc != 3) goto usage_error;
    name = argv[2];
    is_stateful = true;
  } else if (strcmp(cmd, "check") == 0) {
    if (argc != 2) goto usage_error;
    is_no_root_cmd = true;
  } else if (strcmp(cmd, "help") == 0) {
    if (argc != 2) goto usage_error;
    is_no_root_cmd = true;
  } else {
    goto usage_error;
  }

  /* Populate cfg with parsed arguments */
  if (name) {
    if (reject_container_name(name) < 0) {
      ret = 1;
      goto cleanup;
    }
    safe_strncpy(cfg.conf.container_name, name, sizeof(cfg.conf.container_name));
  }
  if (config_path) {
    safe_strncpy(cfg.rt.config_file, config_path, sizeof(cfg.rt.config_file));
  }
  cfg.rt.foreground = foreground ? 1 : 0;

  /*
   * Daemon Proxying:
   * Optimistically attempt to proxy commands to the background daemon.
   * If the daemon is not reachable, fall back to direct execution.
   */
  if (!is_daemon_cmd && !is_no_root_cmd && getenv("NO_PROXY") == nullptr) {
    const int proxy_ret = client_run(argc - 1, argv + 1);
    if (proxy_ret != -2) {
      ret = proxy_ret;
      goto cleanup;
    }
  }

  /* Unified root gate: block all non-exempt commands before any work begins */
  if (!is_no_root_cmd && getuid() != 0) {
    log_error("Root privileges required for '%s'", cmd);
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
  bool loaded = false;
  constexpr char temp_i[PATH_MAX] = "";

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

  ensure_runtime();

  /* single container only */
  if (strcmp(cmd, "start") == 0) {
    if (validate_configuration_cli(&cfg.conf) < 0) {
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
    ret = start_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "stop") == 0) {
    ret = stop_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "info") == 0) {
    ret = show_info(&cfg, false);
    goto cleanup;
  }

  if (strcmp(cmd, "daemon") == 0) {
    if (strcmp(subcmd, "start") == 0) {
      ret = daemon_run(cfg.rt.foreground);
    } else if (strcmp(subcmd, "stop") == 0) {
      /* 如果执行到这里，说明 Daemon 没启动（client_run 代理失败并回退了） */
      log_info("Daemon is not running.");
      ret = 0;
    }
    goto cleanup;
  }

  // Fallback (should be unreachable due to previous strict checking)
  goto usage_error;

usage_error:
  log_error("Invalid arguments or missing command.");
  log_info("Run '%s help' for usage information.", argv[0]);
  ret = 1;

cleanup:
  return ret;
}
