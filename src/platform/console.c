#include "asc.h"

int console_monitor_loop(int console_master_fd, pid_t monitor_pid, cfg_t *cfg) {
  auto_close int epfd = -1, sfd = -1;
  sigset_t mask;
  struct signalfd_siginfo fdsi;
  struct epoll_event ev, events[10];
  char buf[4096];
  ssize_t n;
  int ret = 0;

  /* Pending write state for non-blocking PTY I/O.
   * When the container stops reading, the PTY buffer fills and write()
   * would block forever — deadlocking the entire event loop including
   * CTRL+ALT+Q.  We use non-blocking I/O + EPOLLOUT backpressure. */
  struct {
    int fd; /* target fd (master_fd or STDOUT_FILENO) */
    char data[4096];
    size_t len;
    size_t off;
  } pending = { .fd = -1 };

  /* Setup signalfd for monitor signals */
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGWINCH);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
    return -1;

  sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0)
    return -1;

  /* Setup epoll */
  epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0)
    return -1;

  /* 1. Watch user stdin */
  ev.events = EPOLLIN;
  ev.data.fd = STDIN_FILENO;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    log_warn("epoll_ctl(stdin) failed: %s", strerror(errno));

  /* 2. Watch PTY master (IN + HUP/ERR; OUT added only when pending data) */
  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
  ev.data.fd = console_master_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, console_master_fd, &ev) < 0)
    log_warn("epoll_ctl(master_fd) failed: %s", strerror(errno));

  /* 3. Watch signalfd */
  ev.events = EPOLLIN;
  ev.data.fd = sfd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev) < 0)
    log_warn("epoll_ctl(sig_fd) failed: %s", strerror(errno));

  /* Make PTY master non-blocking — the foundation of the backpressure fix */
  {
    int fl = fcntl(console_master_fd, F_GETFL);
    if (fl >= 0)
      fcntl(console_master_fd, F_SETFL, fl | O_NONBLOCK);
  }

  /* Set terminal to raw mode */
  struct termios oldtios;
  int is_tty = setup_tios(STDIN_FILENO, &oldtios);

  /* Initial window size sync */
  if (is_tty == 0) {
    struct winsize ws;
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
        /* User input -> Container master */
        n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
          /* Check for CTRL+ALT+Q (\x1b\x11) escape sequence */
          if (n >= 2 && buf[0] == '\x1b' && buf[1] == '\x11') {
            static bool exit_detected = false;
            if (!exit_detected) {
              pid_t bg_pid = fork();
              if (bg_pid == 0) {
                setsid();
                log_silent = 1;
                stop_rootfs(cfg);
                _exit(0);
              } else if (bg_pid > 0) {
                exit_detected = true;
              }
            }
            continue;
          }

          /* Write to master_fd.  If the PTY buffer is full (container not
           * reading), buffer the data and register EPOLLOUT. */
          if (pending.fd < 0) {
            ssize_t w = write(console_master_fd, buf, (size_t)n);
            if (w >= 0 && (size_t)w < (size_t)n) {
              pending.fd = console_master_fd;
              pending.len = (size_t)n - (size_t)w;
              pending.off = 0;
              memcpy(pending.data, buf + w, pending.len);
              ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
              ev.data.fd = console_master_fd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
            } else if (w < 0 && errno == EAGAIN) {
              pending.fd = console_master_fd;
              pending.len = (size_t)n;
              pending.off = 0;
              memcpy(pending.data, buf, pending.len);
              ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
              ev.data.fd = console_master_fd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
            } else if (w < 0) {
              running = false;
              break;
            }
          } else {
            /* Already have pending data — drop this input; container
             * is not consuming fast enough. */
          }
        }
      } else if (fd == console_master_fd) {
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          running = false;
          break;
        }

        /* Drain pending writes first (EPOLLOUT) */
        if (events[i].events & EPOLLOUT && pending.fd == console_master_fd) {
          ssize_t w = write(console_master_fd, pending.data + pending.off, pending.len);
          if (w > 0) {
            pending.off += (size_t)w;
            pending.len -= (size_t)w;
          }
          if (pending.len == 0 || (w < 0 && errno != EAGAIN)) {
            pending.fd = -1;
            ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
            ev.data.fd = console_master_fd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, console_master_fd, &ev);
          }
        }

        /* Container output -> User stdout (EPOLLIN) */
        if (events[i].events & EPOLLIN) {
          n = read(console_master_fd, buf, sizeof(buf));
          if (n > 0) {
            [[maybe_unused]] ssize_t w = write(STDOUT_FILENO, buf, (size_t)n);
            /* best-effort; partial is fine */
          } else {
            running = false;
          }
        }
      } else if (fd == sfd) {
        /* Signal handling */
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
          struct winsize ws;
          if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
            ioctl(console_master_fd, TIOCSWINSZ, &ws);
        } else if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
          pid_t live_pid = find_container_init_pid(cfg->conf.uuid);
          if (live_pid > 0)
            kill(live_pid, (int)fdsi.ssi_signo);
        }
      }
    }
  }

  /* Restore terminal settings */
  if (is_tty == 0) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldtios);
  }

  return ret;
}
