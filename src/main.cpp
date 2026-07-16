#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "common.h"
#include "core.h"
#include "utils/log.h"
#include "utils/string.h"
#include "utils/workspace.h"
#include "version.h"

static void print_usage(const char *prog_name) {
  printf("用法: %s <命令> [参数]\r\n", prog_name);
  printf("命令列表:\r\n");
  printf("  start NAME [CONFIG]  使用 CONFIG 配置文件启动名为 NAME 的容器\r\n");
  printf("  stop  NAME           停止名为 NAME 的容器\r\n");
  printf("  help                 显示此帮助信息\r\n");
}

static int print_usage_error(const char *prog_name) {
  printf("无效的参数或缺失命令。\r\n");
  printf("运行 '%s help' 获取使用帮助。\r\n", prog_name);
  return 1;
}

enum class Command {
  START, STOP, HELP, UNKNOWN
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

  if (cmd_str == "start" && argc == 4) {
    cmd = Command::START; name = argv[2]; config_path = argv[3];
  } else if (cmd_str == "stop" && argc == 3) {
    cmd = Command::STOP; name = argv[2];
  } else if (cmd_str == "help" && argc == 2) {
    cmd = Command::HELP;
  } else {
    return print_usage_error(argv[0]);
  }

  if (cmd == Command::HELP) {
    print_usage(argv[0]);
    return 0;
  }

  if (getuid() != 0) {
    printf("执行 '%.*s' 命令需要 Root 权限\r\n", static_cast<int>(cmd_str.size()), cmd_str.data());
    return 1;
  }

  if (reject_container_name(name) < 0) {
    printf("非法的容器名\r\n");
    return 1;
  }

  switch (cmd) {
    case Command::START: {
      if (asc::core::check_requirements_hw() < 0) return 1;
      ensure_runtime();

      asc::rt rt = {};
      rt.foreground = true;
      rt.container_name = name;

      if (config_path[0]) {
        if (asc::core::config_load(config_path, rt.conf) < 0) {
          log_error("无法从 '{}' 加载配置: {}", config_path, strerror(errno));
          return 1;
        }
      }

      print_privileged_warning(rt.conf.privileged_mask);
      if ((rt.conf.privileged_mask & PRIV_NOSEC) && rt.conf.block_nested_ns) {
        log_warn("警告：由于启用了 privileged=noseccomp，block-nested-namespaces 已失效。");
      }
      return asc::core::start_rootfs(rt);
    }
    case Command::STOP: {
      return asc::core::stop_rootfs(name);
    }
    default:
      return 1;
  }
}

int main(int argc, char **argv) {
  return asc_main(argc, argv);
}