#include "asc.h"

/*
 * !!! 我们假设本程序在除了系统关机外不会被意外杀死 !!!
 * !!! 所以我们移除了部分意外防护代码，仅保留了正常情况的处理 !!!
 * !!! 若程序意外退出，必须重启系统进行清理 !!!
 */

static void print_usage() {
  printf(
      "用法: " PROJECT_NAME " <命令> [参数]\n\n"
      "命令列表:\n"
      "  daemon start [-f]         启动后台守护进程 (使用 -f 可在前台运行)\n"
      "  daemon stop               停止正在运行的后台守护进程\n"
      "  start NAME [CONFIG] [-f]  使用可选的 CONFIG 配置文件启动名为 NAME 的容器\n"
      "  stop NAME                 停止名为 NAME 的容器\n"
      "  info NAME                 显示详细的容器信息\n"
      "  help                      显示此帮助信息\n\n");
}

int main(const int argc, char **argv) {
  if (argc < 2) {
    print_usage();
    return 1;
  }

  int ret = 0;
  cfg_t cfg = {};
  bool loaded = false;
  const char *cmd = argv[1];
  const char *subcmd = nullptr;
  const char *name = nullptr;
  const char *config_path = nullptr;
  bool foreground = false;
  bool is_daemon_cmd = false;
  bool is_no_root_cmd = false;
  bool is_stateful = false;

  /* 严格的命令行匹配 */
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
  } else if (strcmp(cmd, "help") == 0) {
    if (argc != 2) goto usage_error;
    is_no_root_cmd = true;
  } else {
    goto usage_error;
  }

  /* 统一 root 权限卡口：在开始任何工作前拦截所有非豁免命令 */
  if (!is_no_root_cmd && getuid() != 0) {
    log_error("执行 '%s' 命令需要 Root 权限", cmd);
    ret = 1;
    goto cleanup;
  }

  /* 用解析后的参数填充 cfg */
  if (name) {
    // 检验容器名合规性
    // 整个程序唯一的container_name来源
    if (reject_container_name(name) < 0) {
      ret = 1;
      goto cleanup;
    }
    safe_strncpy(cfg.rt.container_name, name, sizeof(cfg.rt.container_name));
  }
  if (config_path) {
    safe_strncpy(cfg.rt.config_file, config_path, sizeof(cfg.rt.config_file));
  }
  cfg.rt.foreground = foreground ? 1 : 0;

  /*
   * 守护进程代理 (Daemon Proxying):
   * 乐观地尝试将命令代理给后台守护进程执行。
   * 如果无法连接到守护进程，则回退到直接执行。
   */
  if (!is_daemon_cmd && !is_no_root_cmd && getenv("NO_PROXY") == nullptr) {
    const int proxy_ret = client_run(argc - 1, argv + 1);
    if (proxy_ret != -2) {
      ret = proxy_ret;
      goto cleanup;
    }
  }

  /* 对于有状态的命令，我们绝对需要一个容器名称。 */
  if (is_stateful && cfg.rt.container_name[0] == '\0') {
    log_error("执行此命令必须指定容器名称。");
    ret = 1;
    goto cleanup;
  }

  // 尝试直接加载配置
  if (cfg.rt.config_file[0]) {
    if (config_load(cfg.rt.config_file, &cfg) < 0) {
      log_error("无法从 '%s' 加载配置: %s", cfg.rt.config_file,
                strerror(errno));
      ret = 1;
      goto cleanup;
    }
    loaded = true;
  }

  /* 如果我们有名称但尚未成功加载配置文件，按名称加载。 */
  if (!loaded && cfg.rt.container_name[0] != '\0') {
    if (config_load_by_name(cfg.rt.container_name, &cfg) < 0) {
      log_error("未找到容器 '%s' 或元数据丢失。", cfg.rt.container_name);
      ret = 1;
      goto cleanup;
    }
  }

  /* 为集中式日志引擎设置全局日志上下文 */
  safe_strncpy(log_container_name, cfg.rt.container_name,
               sizeof(log_container_name));

  /* 基础信息命令 */
  if (strcmp(cmd, "help") == 0) {
    print_usage();
    ret = 0;
    goto cleanup;
  }

  ensure_runtime();

  /* 容器启动流程 */
  if (strcmp(cmd, "start") == 0) {
    if (check_requirements_hw() < 0) {
      ret = 1;
      goto cleanup;
    }
    print_privileged_warning(cfg.conf.privileged_mask);
    if (cfg.conf.privileged_mask & PRIV_NOSEC && cfg.conf.block_nested_ns)
      log_warn("警告：由于启用了 privileged=noseccomp，block-nested-namespaces 已失效。");
    ret = start_rootfs(&cfg);
    goto cleanup;
  }

  if (strcmp(cmd, "stop") == 0) {
    ret = stop_rootfs(&cfg.rt);
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
      char *stop_args[] = {(char*)"daemon-stop", nullptr};
      if (client_run(1, stop_args) == -2) {
        log_info("守护进程当前未运行。");
      }
      ret = 0;
    }
    goto cleanup;
  }

usage_error:
  log_error("无效的参数或缺失命令。");
  log_info("运行 '%s help' 获取使用帮助。", argv[0]);
  ret = 1;

cleanup:
  return ret;
}