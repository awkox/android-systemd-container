#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "common.h"
#include "core/check.h"
#include "core/config.h"
#include "core/container.h"
#include "utils/log.h"
#include "utils/string.h"
#include "utils/logger.h"
#include "utils/workspace.h"
#include "version.h"

/*
 * !!! 我们假设本程序在除了系统关机外不会被意外杀死 !!!
 * !!! 所以我们移除了部分意外防护代码，仅保留了正常情况的处理 !!!
 * !!! 若程序意外退出，必须重启系统进行清理 !!!
 */

static void print_usage(const char *prog_name) {
  printf("用法: %s <命令> [参数]", prog_name);
  printf("命令列表:");
  printf("  start NAME [CONFIG]  使用 CONFIG 配置文件启动名为 NAME 的容器");
  printf("  stop  NAME           停止名为 NAME 的容器");
  printf("  help                 显示此帮助信息");
}

static int print_usage_error(const char *prog_name) {
  printf("无效的参数或缺失命令。");
  printf("运行 '%s help' 获取使用帮助。", prog_name);
  return 1;
}

enum class Command {
  START,
  STOP,
  HELP,
  UNKNOWN
};

int asc_main(int argc, char **argv) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  std::string_view cmd_str = argv[1];
  Command cmd = Command::UNKNOWN;
  const char *name = nullptr;
  const char *config_path = nullptr;

  /* 1. 解析命令与参数 */
  if (cmd_str == "start" && argc == 4) {
    cmd = Command::START;
    name = argv[2];
    config_path = argv[3];
  } else if (cmd_str == "stop" && argc == 3) {
    cmd = Command::STOP;
    name = argv[2];
  } else if (cmd_str == "help" && argc == 2) {
    cmd = Command::HELP;
  } else {
    return print_usage_error(argv[0]);
  }

  /* 2. 基础信息命令 (无需 Root 权限) */
  if (cmd == Command::HELP) {
    print_usage(argv[0]);
    return 0;
  }

  /* 3. 统一 Root 权限安全拦截口 */
  if (getuid() != 0) {
    printf("执行 '%.*s' 命令需要 Root 权限", static_cast<int>(cmd_str.size()), cmd_str.data());
    return 1;
  }

  if (reject_container_name(name) < 0) {
    printf("非法的容器名");
    return 1;
  }

  /* 4. 分发至相应的生命周期管理核心 */
  switch (cmd) {
    case Command::START: {
      if (check_requirements_hw() < 0) {
        return 1;
      }

      ensure_runtime();

      cfg_t cfg = {};
      cfg.rt.foreground = true;
      cfg.rt.container_name = name;

      /* 5. 尝试加载容器配置文件 */
      if (config_path[0]) {
        if (config_load(config_path, cfg.conf) < 0) {
          log_error("无法从 '%s' 加载配置: %s", config_path, strerror(errno));
          return 1;
        }
      }

      print_privileged_warning(cfg.conf.privileged_mask);
      if ((cfg.conf.privileged_mask & PRIV_NOSEC) && cfg.conf.block_nested_ns) {
        log_warn("警告：由于启用了 privileged=noseccomp，block-nested-namespaces 已失效。");
      }
      return start_rootfs(cfg);
    }

    case Command::STOP: {
      return stop_rootfs(name);
    }

    default:
      return 1;
  }
}

int main(int argc, char **argv) {
  return asc_main(argc, argv);
}