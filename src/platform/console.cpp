#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>
#include <termios.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <string_view>

#include "platform/console.h"
#include "platform/pty.h"
#include "utils/process.h"
#include "utils/log.h"

/* 定义控制台上下文，避免在拆分的函数中传递大量参数 */
struct ConsoleContext {
  int epfd;
  int console_master_fd;
  int sfd;
  int pidfd;
  pid_t monitor_pid;
  std::string_view container_name;
  bool running;

  /* 挂起的写入状态，用于非阻塞 PTY I/O 的背压处理 */
  struct {
    int fd;
    char data[4096];
    size_t len;
    size_t off;
  } pending;
};

/* 1. 处理来自用户标准输入 (STDIN) 的事件 */
static void handle_stdin_event(ConsoleContext &ctx, uint32_t /* events */) {
  char buf[4096];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
  if (n <= 0) return;

  /* 透传至 PTY Master (带有背压处理) */
  if (ctx.console_master_fd >= 0 && ctx.pending.fd < 0) {
    ssize_t w = write(ctx.console_master_fd, buf, static_cast<size_t>(n));
    epoll_event ev = {};
    ev.data.fd = ctx.console_master_fd;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;

    if (w >= 0 && static_cast<size_t>(w) < static_cast<size_t>(n)) {
      ctx.pending.fd = ctx.console_master_fd;
      ctx.pending.len = static_cast<size_t>(n) - static_cast<size_t>(w);
      ctx.pending.off = 0;
      memcpy(ctx.pending.data, buf + w, ctx.pending.len);
      epoll_ctl(ctx.epfd, EPOLL_CTL_MOD, ctx.console_master_fd, &ev);
    } else if (w < 0 && errno == EAGAIN) {
      ctx.pending.fd = ctx.console_master_fd;
      ctx.pending.len = static_cast<size_t>(n);
      ctx.pending.off = 0;
      memcpy(ctx.pending.data, buf, ctx.pending.len);
      epoll_ctl(ctx.epfd, EPOLL_CTL_MOD, ctx.console_master_fd, &ev);
    } else if (w < 0) {
      epoll_ctl(ctx.epfd, EPOLL_CTL_DEL, ctx.console_master_fd, nullptr);
      close(ctx.console_master_fd);
      ctx.console_master_fd = -1;
    }
  }
}

/* 2. 处理容器 PTY Master 的事件 (读输出、写挂起数据、挂断) */
static void handle_pty_event(ConsoleContext &ctx, uint32_t events) {
  /* 容器断开控制台（如关机阶段），取消监听但不退出，等待 Monitor 信号 */
  if (events & (EPOLLHUP | EPOLLERR)) {
    epoll_ctl(ctx.epfd, EPOLL_CTL_DEL, ctx.console_master_fd, nullptr);
    close(ctx.console_master_fd);
    ctx.console_master_fd = -1;
    return;
  }

  /* 优先排空挂起的写入 (EPOLLOUT) */
  if ((events & EPOLLOUT) && ctx.pending.fd == ctx.console_master_fd) {
    ssize_t w = write(ctx.console_master_fd, ctx.pending.data + ctx.pending.off, ctx.pending.len);
    if (w > 0) {
      ctx.pending.off += static_cast<size_t>(w);
      ctx.pending.len -= static_cast<size_t>(w);
    }
    if (ctx.pending.len == 0 || (w < 0 && errno != EAGAIN)) {
      ctx.pending.fd = -1;
      epoll_event ev = {};
      ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
      ev.data.fd = ctx.console_master_fd;
      epoll_ctl(ctx.epfd, EPOLL_CTL_MOD, ctx.console_master_fd, &ev);
    }
  }

  /* 容器输出 -> 用户 stdout (EPOLLIN) */
  if (events & EPOLLIN) {
    char buf[4096];
    ssize_t n = read(ctx.console_master_fd, buf, sizeof(buf));
    if (n > 0) {
      [[maybe_unused]] ssize_t w = write(STDOUT_FILENO, buf, static_cast<size_t>(n));
    } else {
      epoll_ctl(ctx.epfd, EPOLL_CTL_DEL, ctx.console_master_fd, nullptr);
      close(ctx.console_master_fd);
      ctx.console_master_fd = -1;
    }
  }
}

/* 3. 处理信号事件 (终端缩放、中断信号) */
static void handle_signal_event(ConsoleContext &ctx, uint32_t /* events */) {
  signalfd_siginfo fdsi;
  if (read(ctx.sfd, &fdsi, sizeof(fdsi)) != sizeof(fdsi)) return;

  if (fdsi.ssi_signo == SIGWINCH) {
    if (ctx.console_master_fd >= 0) {
      winsize ws;
      if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
        ioctl(ctx.console_master_fd, TIOCSWINSZ, &ws);
    }
  } else if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
    pid_t live_pid = find_container_init_pid(ctx.container_name);
    if (live_pid > 0)
      kill(live_pid, static_cast<int>(fdsi.ssi_signo));
  }
}

/* 处理 Monitor 进程的退出事件 (pidfd 可读) */
static void handle_pidfd_event(ConsoleContext &ctx, uint32_t /* events */) {
  int status;
  // 由于 epoll 已经通知我们该进程退出了，因此使用 WNOHANG 非阻塞清理僵尸进程即可
  waitpid(ctx.monitor_pid, &status, WNOHANG);
  ctx.running = false;
}

int console_monitor_loop(int console_master_fd, pid_t monitor_pid, std::string_view container_name) {
  int ret = 0;
  int is_tty = -1;
  termios oldtios;
  
  ConsoleContext ctx = {
    .epfd = -1,
    .console_master_fd = console_master_fd,
    .sfd = -1,
    .pidfd = -1,            // 初始化 pidfd
    .monitor_pid = monitor_pid,
    .container_name = container_name,
    .running = true,
    .pending = {},
  };

  ctx.pending.fd = -1;

  sigset_t mask;
  epoll_event ev = {}, events[10] = {};

  /* 1. 设置 signalfd (移除 SIGCHLD) */
  sigemptyset(&mask);
  // 注意：不再阻塞和监听 SIGCHLD
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGWINCH);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    ret = -1;
    goto cleanup;
  }
  ctx.sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (ctx.sfd < 0) {
    ret = -1;
    goto cleanup;
  }

  /* 2. 设置 epoll */
  ctx.epfd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx.epfd < 0) {
    ret = -1;
    goto cleanup;
  }

  /* --- 新增：打开 monitor 进程的 pidfd --- */
  ctx.pidfd = syscall(SYS_pidfd_open, ctx.monitor_pid, 0);
  if (ctx.pidfd < 0) {
    log_error("无法为 monitor 获取 pidfd: {}", strerror(errno));
    ret = -1;
    goto cleanup;
  }

  /* 注册监听事件 */
  ev.events = EPOLLIN;
  ev.data.fd = STDIN_FILENO;
  epoll_ctl(ctx.epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
  ev.data.fd = ctx.console_master_fd;
  epoll_ctl(ctx.epfd, EPOLL_CTL_ADD, ctx.console_master_fd, &ev);

  ev.events = EPOLLIN;
  ev.data.fd = ctx.sfd;
  epoll_ctl(ctx.epfd, EPOLL_CTL_ADD, ctx.sfd, &ev);

  /* 将 pidfd 注册到 epoll 中 (退出的子进程在 epoll 中表现为 EPOLLIN 可读) */
  ev.events = EPOLLIN;
  ev.data.fd = ctx.pidfd;
  epoll_ctl(ctx.epfd, EPOLL_CTL_ADD, ctx.pidfd, &ev);

  /* 将 PTY master 设为非阻塞模式 */
  if (int fl = fcntl(ctx.console_master_fd, F_GETFL); fl >= 0) {
    fcntl(ctx.console_master_fd, F_SETFL, fl | O_NONBLOCK);
  }

  /* 设置终端为原始(raw)模式 */
  is_tty = setup_tios(STDIN_FILENO, oldtios);
  if (is_tty == 0) {
    winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(ctx.console_master_fd, TIOCSWINSZ, &ws);
  }

  /* 3. 进入主事件分发循环 (Dispatcher) */
  while (ctx.running) {
    int nfds = epoll_wait(ctx.epfd, events, 10, -1);
    if (nfds < 0) {
      if (errno == EINTR) continue;
      ret = -1;
      break;
    }

    for (int i = 0; i < nfds; i++) {
      const int fd = events[i].data.fd;
      const uint32_t ev_mask = events[i].events;

      if (fd == STDIN_FILENO) {
        handle_stdin_event(ctx, ev_mask);
      } else if (fd == ctx.console_master_fd) {
        handle_pty_event(ctx, ev_mask);
      } else if (fd == ctx.sfd) {
        handle_signal_event(ctx, ev_mask);
      } else if (fd == ctx.pidfd) {
        handle_pidfd_event(ctx, ev_mask);
      }
    }
  }

  /* 4. 手动清理分配的资源 */
cleanup:
  if (ctx.pidfd >= 0) close(ctx.pidfd);
  if (ctx.sfd >= 0) close(ctx.sfd);
  if (ctx.epfd >= 0) close(ctx.epfd);
  if (ctx.console_master_fd >= 0) close(ctx.console_master_fd);
  if (is_tty == 0) tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldtios);

  return ret;
}