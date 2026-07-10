#include "asc.h"

int client_run(int argc, char **argv) {
  auto_close int winch_sfd = -1;
  auto_close int epfd = -1;
  auto_close int sock = -1;
  struct termios orig = {};
  bool raw_tty_active = false;
  int exit_code = 0;
  char buf[IOBUF];
  struct epoll_event ev = {};
  struct epoll_event events[4] = {};
  struct sockaddr_un addr = {};

  if (argc < 1)
    return -2;

  bool interactive = (strcmp(argv[0], "start") == 0);
  bool has_tty = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);

  if (interactive && !has_tty) {
    interactive = false;
  }

  const socklen_t alen = make_addr(&addr);

  sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0) {
    fprintf(stderr, "client: 套接字创建失败: %s\n", strerror(errno));
    return 1;
  }
  if (connect(sock, reinterpret_cast<struct sockaddr *>(&addr), alen) < 0) {
    int err = errno;
    if (err == ECONNREFUSED || err == ENOENT)
      return -2;
    fprintf(stderr, "[-] 无法连接到 Daemon 守护进程: %s\n", strerror(err));
    return 1;
  }

  uint32_t flags = interactive ? REQ_FLAG_PTY : 0u;
  uint32_t nf = htonl(flags), na = htonl(static_cast<uint32_t>(argc));
  if (write_all(sock, &nf, 4) < 0 || write_all(sock, &na, 4) < 0)
    goto send_err;

  for (int i = 0; i < argc; i++) {
    uint32_t al = static_cast<uint32_t>(strlen(argv[i])), nal = htonl(al);
    if (write_all(sock, &nal, 4) < 0)
      goto send_err;
    if (al && write_all(sock, argv[i], al) < 0)
      goto send_err;
  }

  if (interactive) {
    struct winsize ws = {24, 80, 0, 0};
    ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
    uint16_t wd[2] = {htons(ws.ws_row), htons(ws.ws_col)};
    if (write_all(sock, wd, 4) < 0)
      goto send_err;
  }

  if (interactive && has_tty && tcgetattr(STDIN_FILENO, &orig) == 0) {
    raw_tty_active = true;
    struct termios raw = orig;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    sigset_t ws;
    sigemptyset(&ws);
    sigaddset(&ws, SIGWINCH);
    sigprocmask(SIG_BLOCK, &ws, nullptr);
    winch_sfd = signalfd(-1, &ws, SFD_NONBLOCK | SFD_CLOEXEC);
  }

  epfd = epoll_create1(EPOLL_CLOEXEC);

  if (raw_tty_active) {
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);
  }
  if (winch_sfd >= 0) {
    ev.events = EPOLLIN;
    ev.data.fd = winch_sfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, winch_sfd, &ev);
  }
  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
  ev.data.fd = sock;
  epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

  for (;;) {
    int nfds = epoll_wait(epfd, events, 4, -1);
    if (nfds < 0 && errno != EINTR)
      break;

    bool done = false;
    for (int i = 0; i < nfds && !done; i++) {
      int fd = events[i].data.fd;

      if (winch_sfd >= 0 && fd == winch_sfd) {
        struct signalfd_siginfo si;
        while (read(winch_sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si))) {
          struct winsize nws = {24, 80, 0, 0};
          ioctl(STDIN_FILENO, TIOCGWINSZ, &nws);
          uint16_t wd2[2] = {htons(nws.ws_row), htons(nws.ws_col)};
          send_frame(sock, MSG_WINCH, wd2, 4);
        }
      } else if (fd == STDIN_FILENO) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
          if (send_frame(sock, MSG_OUT, buf, static_cast<uint32_t>(n)) < 0)
            done = true;
        } else {
          done = true;
        }
      } else if (fd == sock) {
        if (events[i].events & EPOLLIN) {
          for (;;) {
            uint8_t type;
            uint32_t mlen;
            if (recv_frame_hdr(sock, &type, &mlen) < 0) {
              done = true;
              break;
            }

            if (type == MSG_EXIT) {
              uint32_t nc = 0;
              if (mlen >= 4)
                read_exact(sock, &nc, 4);
              exit_code = static_cast<int>(ntohl(nc));
              done = true;
              break;
            }

            FILE *dest = type == MSG_ERR ? stderr : stdout;
            uint32_t rem = mlen;
            while (rem) {
              uint32_t c =
                  rem < static_cast<uint32_t>(sizeof(buf)) ? rem : static_cast<uint32_t>(sizeof(buf));
              if (read_exact(sock, buf, c) < 0) {
                done = true;
                break;
              }
              fwrite(buf, 1, c, dest);
              rem -= c;
            }
            fflush(dest);
            if (done)
              break;

            struct pollfd pfd = {sock, POLLIN, 0};
            if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN))
              break;
          }
        }

        if (!done && events[i].events & (EPOLLHUP | EPOLLERR)) {
          done = true;
          break;
        }
      }
    }
    if (done)
      break;
  }

  if (raw_tty_active) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);
    if (winch_sfd >= 0) {
      sigset_t ws;
      sigemptyset(&ws);
      sigaddset(&ws, SIGWINCH);
      sigprocmask(SIG_UNBLOCK, &ws, nullptr);
    }
  }
  return exit_code;

send_err:
  fprintf(stderr, "client: 发送数据失败: %s\n", strerror(errno));
  return 1;
}
