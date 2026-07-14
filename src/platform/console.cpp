#include "asc.h"

int console_monitor_loop(int console_master_fd, pid_t monitor_pid, cfg_t *cfg) {
  sigset_t mask;
  signalfd_siginfo fdsi;
  epoll_event ev = {}, events[10] = {};
  char buf[4096];
  ssize_t n;
  int ret = 0;

  /* 挂起的写入状态，用于非阻塞 PTY I/O。
   * 当容器停止读取时，PTY 缓冲区填满，常规 write() 将永远阻塞
   * 进而死锁包括 CTRL+ALT+Q 在内的整个事件循环。
   * 此处我们使用非阻塞 I/O 和 EPOLLOUT 背压机制。 */
  struct {
    int fd; 
    char data[4096];
    size_t len;
    size_t off;
  } pending = {};
  pending.fd = -1;

  /* 设置 signalfd 以捕获监控进程信号 */
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGWINCH);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
    return -1;

  int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0)
    return -1;

  /* 设置 epoll */
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    close(sfd);
    return -1;
  }

  /* 1. 监控用户标准输入 (stdin) */
  ev.events = EPOLLIN;
  ev.data.fd = STDIN_FILENO;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    log_warn("epoll_ctl(stdin) 失败: %s", strerror(errno));

  /* 2. 监控 PTY master (IN + HUP/ERR; 只有当有待写入数据时才添加 OUT) */
  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
  ev.data.fd = console_master_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, console_master_fd, &ev) < 0)
    log_warn("epoll_ctl(master_fd) 失败: %s", strerror(errno));

  /* 3. 监控 signalfd */
  ev.events = EPOLLIN;
  ev.data.fd = sfd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev) < 0)
    log_warn("epoll_ctl(sig_fd) 失败: %s", strerror(errno));

  /* 将 PTY master 设为非阻塞模式 — 这是背压修复的基础 */
  {
    int fl = fcntl(console_master_fd, F_GETFL);
    if (fl >= 0)
      fcntl(console_master_fd, F_SETFL, fl | O_NONBLOCK);
  }

  /* 设置终端为原始(raw)模式 */
  termios oldtios;
  int is_tty = setup_tios(STDIN_FILENO, &oldtios);

  /* 初始同步窗口尺寸 */
  if (is_tty == 0) {
    winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
      ioctl(console_master_fd, TIOCSWINSZ, &ws);
  }

  bool running = true;
  while (running) {
    int nfds = epoll_wait(epfd, events, 10, -1);
    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      ret = -1;
      break;
    }

    for (int i = 0; i < nfds; i++) {
      int fd = events[i].data.fd;

      if (fd == STDIN_FILENO) {
        /* 用户输入 -> 容器 PTY Master */
        n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
          /* 拦截检查 CTRL+ALT+Q (\x1b\x11) 逃逸序列 */
          if (n >= 2 && buf[0] == '\x1b' && buf[1] == '\x11') {
            static bool exit_detected = false;
            if (!exit_detected) {
              pid_t bg_pid = fork();
              if (bg_pid == 0) {
                setsid();
                stop_rootfs(cfg->rt.container_name);
                _exit(0);
              }
              if (bg_pid > 0) {
                exit_detected = true;
              }
            }
            continue;
          }

          /* 修复：只有当 console_master_fd 仍然有效时才写入 */
          if (console_master_fd >= 0) {
            if (pending.fd < 0) {
              ssize_t w = write(console_master_fd, buf, static_cast<size_t>(n));
              if (w >= 0 && static_cast<size_t>(w) < static_cast<size_t>(n)) {
                pending.fd = console_master_fd;
                pending.len = static_cast<size_t>(n) - static_cast<size_t>(w);
                pending.off = 0;
                memcpy(pending.data, buf + w, pending.len);
                ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
                ev.data.fd = console_master_fd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
              } else if (w < 0 && errno == EAGAIN) {
                pending.fd = console_master_fd;
                pending.len = static_cast<size_t>(n);
                pending.off = 0;
                memcpy(pending.data, buf, pending.len);
                ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
                ev.data.fd = console_master_fd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
              } else if (w < 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, console_master_fd, nullptr);
                close(console_master_fd);
                console_master_fd = -1;
              }
            }
          }
        }
      } else if (fd == console_master_fd) {
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          /* 修复：容器断开控制台（如关机阶段），取消监听但不退出，等待 Monitor 信号 */
          epoll_ctl(epfd, EPOLL_CTL_DEL, console_master_fd, nullptr);
          console_master_fd = -1;
          continue;
        }

        /* 优先排空挂起的写入 (EPOLLOUT) */
        if (events[i].events & EPOLLOUT && pending.fd == console_master_fd) {
          ssize_t w = write(console_master_fd, pending.data + pending.off, pending.len);
          if (w > 0) {
            pending.off += static_cast<size_t>(w);
            pending.len -= static_cast<size_t>(w);
          }
          if (pending.len == 0 || (w < 0 && errno != EAGAIN)) {
            pending.fd = -1;
            ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
            ev.data.fd = console_master_fd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
          }
        }

        /* 容器输出 -> 用户 stdout (EPOLLIN) */
        if (events[i].events & EPOLLIN) {
          n = read(console_master_fd, buf, sizeof(buf));
          if (n > 0) {
            [[maybe_unused]] ssize_t w = write(STDOUT_FILENO, buf, static_cast<size_t>(n));
          } else {
            epoll_ctl(epfd, EPOLL_CTL_DEL, console_master_fd, nullptr);
            close(console_master_fd);
            console_master_fd = -1;
          }
        }
      } else if (fd == sfd) {
        /* 处理监听到的信号 */
        n = read(sfd, &fdsi, sizeof(fdsi));
        if (n != sizeof(fdsi))
          continue;

        if (fdsi.ssi_signo == SIGCHLD) {
          int status;
          pid_t child = waitpid(monitor_pid, &status, WNOHANG);
          if (child == monitor_pid) {
            running = false;
          }
        } else if (fdsi.ssi_signo == SIGWINCH) {
          winsize ws;
          if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
            ioctl(console_master_fd, TIOCSWINSZ, &ws);
        } else if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
          pid_t live_pid = find_container_init_pid(cfg->rt.container_name);
          if (live_pid > 0)
            kill(live_pid, static_cast<int>(fdsi.ssi_signo));
        }
      }
    }
  }

  close(sfd);
  close(epfd);

  /* 恢复原本的终端设置 */
  if (is_tty == 0) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldtios);
  }

  return ret;
}