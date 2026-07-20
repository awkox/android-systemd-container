#include <unistd.h>
#include <poll.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <format>
#include <filesystem>
#include <string>

#include "core.h"
#include "utils/log.h"
#include "utils/fileio.h"
#include "utils/path.h"
#include "utils/system.h"
#include "utils/process.h"
#include "platform/pty.h"
#include "common.h"

namespace asc::core {

namespace {

struct InitArgs {
  asc::rt &rt;
  int efd;              // 替代原有的读写管道，仅需一个 fd
  int sync_pipe_write;  // 属于 Monitor 向 CLI 通信的写端（Init应关闭）
};

constexpr int REBOOT_EXIT = 249;

int init_trampoline(void *arg) {
  InitArgs *args = static_cast<InitArgs *>(arg);
  
  // 1. 修复 FD 泄漏：显式关闭继承自父进程但属于父进程的管道写端
  if (args->sync_pipe_write >= 0) close(args->sync_pipe_write);

  /* 2. 阻塞等待父进程(Monitor)将我们安全迁入 Cgroup 树 */
  uint64_t wake_val = 0;
  if (read(args->efd, &wake_val, sizeof(wake_val)) != sizeof(wake_val)) {
    log_error("Init 进程读取同步信号失败: {}", strerror(errno));
    return -1;
  }
  close(args->efd); // 消费完毕，安全关闭

  /* 现在我们在正确的 Cgroup 中，执行 Cgroup 命名空间隔离锁定 */
  if (unshare(CLONE_NEWCGROUP) < 0) {
    log_error("Init Cgroup 隔离失败: {}", strerror(errno));
    return -1;
  }

  internal_boot(args->rt);
  return -1; 
}

// 子模块 1: 环境与上下文初始化
void setup_monitor_environment(asc::rt &rt) {
  if (setsid() < 0 && errno != EPERM) {
    log_error("Monitor setsid 失败: {}", strerror(errno));
    _exit(EXIT_FAILURE);
  }

  /* 忽略挂断及其他中断，防止意外终止。(SIGTERM/SIGINT 交由 signalfd 处理) */
  signal(SIGQUIT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  
  oom_protect();
  prctl(PR_SET_NAME, "[ds-monitor]", 0, 0, 0);

  std::filesystem::path cg_path = project_cgroup_dir / rt.container_name;
  create_directories_with_permission(cg_path);
}

// 子模块 2: 后台模式 IO 重定向
void redirect_stdio_to_null() {
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    terminal_set_stdfds(devnull);
    close(devnull);
  }
}

// 子模块 3: 孵化与唤醒容器 Init 进程
pid_t launch_container_init(asc::rt &rt, void *stack_top, int &sync_fd) {
  // 使用 eventfd 替代 pipe，创建一个纯内存的 64 位计数器对象
  int efd = eventfd(0, EFD_CLOEXEC);
  if (efd < 0) {
    log_error("分配 eventfd 失败: {}", strerror(errno));
    return -1;
  }

  InitArgs args = {rt, efd, sync_fd};
  int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
  if (rt.cfg.isolation_network) clone_flags |= CLONE_NEWNET;

  pid_t init_pid = clone(init_trampoline, stack_top, clone_flags, &args);

  if (init_pid < 0) {
    log_error("clone 容器进程失败: {}", strerror(errno));
    close(efd); // 发生错误，清理 efd
    return -1;
  }

  /* 将子进程迁入 Cgroup */
  std::filesystem::path cg_path = project_cgroup_dir / rt.container_name;
  write_file(cg_path / "cgroup.procs", std::format("{}\n", init_pid));

  /* 释放 Init 进程，允许其推进引导 */
  uint64_t wake_val = 1; // 必须写入 8 字节 (uint64_t)
  if (write(efd, &wake_val, sizeof(wake_val)) < 0) {
    log_warn("唤醒 Init 进程警告: {}", strerror(errno));
  }
  close(efd); // 写入后父进程即关闭，不影响子进程持有

  /* 首次启动时通知 CLI 工具 */
  if (sync_fd >= 0) {
    if (write(sync_fd, &init_pid, sizeof(pid_t)) != sizeof(pid_t)) {}
    close(sync_fd);
    sync_fd = -1; // 标记为已消费
  }

  return init_pid;
}

// 子模块 4: 高效阻塞等待容器退出
int wait_for_container_exit(pid_t init_pid, int sfd) {
  int pfd = syscall(SYS_pidfd_open, init_pid, 0);
  if (pfd < 0) {
    log_error("pidfd_open失败：{}", strerror(errno));
    return -1;
  }

  pollfd pfds[2] = {
      {.fd = pfd, .events = POLLIN, .revents = 0},
      {.fd = sfd, .events = POLLIN, .revents = 0}
  };
  
  // 阻塞等待：目标进程退出 OR 收到前台代理信号
  while (true) {
    if (poll(pfds, 2, -1) < 0) {
      if (errno == EINTR) continue;
      break;
    }

    // 1. 处理来自 CLI 前台透传过来的关机信号
    if (pfds[1].revents & POLLIN) {
      signalfd_siginfo fdsi;
      while (read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi)) {
        if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
          kill(init_pid, fdsi.ssi_signo);
        }
      }
    }

    // 2. 优先判定容器是否退出 (即使上面刚发信号，这里也正常监测)
    if (pfds[0].revents & POLLIN) {
      break;
    }
  }

  int status = 0;
  // 直接回收退出状态
  waitpid(init_pid, &status, 0);
  close(pfd);
  
  return status;
}

// 子模块 5: 退出状态分析与重启决策
bool evaluate_reboot_request(int status, asc::rt &rt) {
  bool is_reboot_request = false;

  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == REBOOT_EXIT) {
      is_reboot_request = true;
      log_info("[MONITOR] 检测到容器内部发起了重启请求 (退出码: {})", code);
    } else {
      log_info("[MONITOR] 检测到容器正常关机 (退出码: {})", code);
    }
  } else if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    if (sig == SIGHUP) {
      is_reboot_request = true;
      log_info("[MONITOR] 检测到容器内部发起了重启请求 (SIGHUP)");
    } else if (sig == SIGINT || sig == (SIGRTMIN + 3) ||
               sig == (SIGRTMIN + 4) || sig == (SIGRTMIN + 13) ||
               sig == (SIGRTMIN + 14)) {
      log_info("[MONITOR] 检测到容器内部发起了关机请求 (Signal {})", sig);
    } else {
      log_warn("[MONITOR] Init 进程被信号异常终止: {} ({})", sig, strsignal(sig));
    }
  }

  if (is_reboot_request) {
    if (is_external_lock_active(rt.container_name)) {
      log_warn("[MONITOR] 检测到外部命令锁 - 中止内部重启，移交控制权给 CLI");
      return false;
    } 
    
    if (rt.foreground) {
      log_info("容器 {} 正在重启", rt.container_name);
      fflush(stdout);
    }
    rt.reboot_cycle = true;

    // 重置运行时 PID 标识以进入下一轮
    rt.container_pid = 0;
    rt.ns_inode = 0;
    return true;
  }
  
  return false;
}

}

// 主函数: monitor_run 监督主循环
void monitor_run(asc::rt &rt, int sync_pipe_write) {
  setup_monitor_environment(rt);

  int sync_fd = sync_pipe_write;
  bool stdio_redirected = false;
  int status = 0;
  bool should_reboot = false;

   // 初始化 Monitor 专属的代理信号监听器
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  
  int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0) {
    log_error("Monitor 无法创建 signalfd: {}", strerror(errno));
    _exit(EXIT_FAILURE);
  }

  constexpr size_t stack_size = 2 * 1024 * 1024;

  do {
    if (!rt.foreground && !stdio_redirected) {
      redirect_stdio_to_null();
      stdio_redirected = true;
    }

    void *stack = malloc(stack_size);
    if (!stack) _exit(EXIT_FAILURE);
    void *stack_top = static_cast<char *>(stack) + stack_size;

    // 1. 孵化 Init 进程
    pid_t init_pid = launch_container_init(rt, stack_top, sync_fd);
    if (init_pid < 0) {
      free(stack);
      _exit(EXIT_FAILURE);
    }

    rt.container_pid = init_pid;
    rt.ns_inode = get_pid_ns_inode(init_pid);
    log_info("容器启动成功，主 PID 为 {} (Monitor PID: {})", init_pid, getpid());

    if (chdir("/") < 0) {
      log_warn("无法 chdir 到 /: {}", strerror(errno));
    }

    // 2. 挂起 Monitor 自身，阻塞监听容器退出及信号
    status = wait_for_container_exit(init_pid, sfd);
    
    // 3. 显式释放栈内存
    free(stack);

    if (status < 0) {
      _exit(EXIT_FAILURE);
    }

    // 4. 判断是否需要自旋重启
    should_reboot = evaluate_reboot_request(status, rt);

  } while (should_reboot);

  if (sfd >= 0) close(sfd);
  log_info("[MONITOR] 容器主进程已退出，Monitor 正在执行退出清理工作...");
  cleanup_container_resources(rt.container_name, false);

  log_info("[MONITOR] 资源清理完毕，守护进程退出。");
  _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 0);
}

}
