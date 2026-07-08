#include "asc.h"

static FILE *g_daemon_log_fp = nullptr;
static char g_daemon_log_path[PATH_MAX] = "";

static void rotate_daemon_log_if_needed(void) {
  if (g_daemon_log_path[0] == '\0')
    return;

  struct stat st;
  if (stat(g_daemon_log_path, &st) < 0 || st.st_size < 4 * 1024 * 1024)
    return;

  char old_path[sizeof(g_daemon_log_path) + 32];
  snprintf(old_path, sizeof(old_path), "%s.old", g_daemon_log_path);
  rename(g_daemon_log_path, old_path);

  if (g_daemon_log_fp) {
    fclose(g_daemon_log_fp);
    g_daemon_log_fp = fopen(g_daemon_log_path, "ae");
  } else {
    const int lfd = open(g_daemon_log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                   0644);
    if (lfd >= 0) {
      dup2(lfd, STDOUT_FILENO);
      dup2(lfd, STDERR_FILENO);
      if (lfd > STDERR_FILENO)
        close(lfd);
    }
  }
}

[[gnu::format(printf, 2, 3)]]
static void daemon_log_tee(const char *prefix, const char *fmt, ...) {
  if (!g_daemon_log_fp)
    return;
  char msg[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  fprintf(g_daemon_log_fp, "[%s] %s\n", prefix, msg);
  fflush(g_daemon_log_fp);
}

#undef log_info
#define log_info(fmt, ...)                                                     \
  do {                                                                         \
    log_internal("+", false, fmt __VA_OPT__(,) __VA_ARGS__);                   \
    daemon_log_tee("+", fmt __VA_OPT__(,) __VA_ARGS__);                        \
  } while (0)

#undef log_warn
#define log_warn(fmt, ...)                                                     \
  do {                                                                         \
    log_internal("!", true, fmt __VA_OPT__(,) __VA_ARGS__);                    \
    daemon_log_tee("!", fmt __VA_OPT__(,) __VA_ARGS__);                        \
  } while (0)

#undef log_error
#define log_error(fmt, ...)                                                    \
  do {                                                                         \
    log_internal("-", true, fmt __VA_OPT__(,) __VA_ARGS__);                    \
    daemon_log_tee("-", fmt __VA_OPT__(,) __VA_ARGS__);                        \
  } while (0)

static char g_self_path[PATH_MAX];
static volatile sig_atomic_t g_sigusr2_received = 0;
static volatile sig_atomic_t g_terminate = 0;

static void reexec(char **argv) {
  const char *path = g_self_path[0] != '\0' ? g_self_path : "/proc/self/exe";
  execv(path, argv);
  _exit(127);
}

static char **make_exec_argv(const req_t *r) {
  char **av = static_cast<char **>(malloc(static_cast<size_t>(r->argc + 2) * sizeof(char *)));
  if (!av)
    return nullptr;
  av[0] = const_cast<char *>(PROJECT_NAME);
  for (int i = 0; i < r->argc; i++)
    av[i + 1] = r->argv[i];
  av[r->argc + 1] = nullptr;
  return av;
}

static void drain_fd(const int fd, const int conn, const uint8_t type) {
  char buf[IOBUF];
  const int fl = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  for (;;) {
    const ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0)
      break;
    send_frame(conn, type, buf, static_cast<uint32_t>(n));
  }
  fcntl(fd, F_SETFL, fl);
}

static void handle_session(int conn, req_t *r) {
  int is_pty = r->flags & REQ_FLAG_PTY;
  int master = -1, slave = -1;
  int out[2] = {-1, -1}, err[2] = {-1, -1};
  char buf[IOBUF];

  if (is_pty) {
    if (asc_openpty(&master, &slave, nullptr) < 0) {
      send_frame(conn, MSG_ERR, "daemon: openpty 失败\n", 23);
      send_exit(conn, 1);
      return;
    }
    struct winsize ws = {r->rows, r->cols, 0, 0};
    ioctl(master, TIOCSWINSZ, &ws);
    fcntl(master, F_SETFD, FD_CLOEXEC);
  } else {
    if (pipe2(out, O_CLOEXEC) < 0 || pipe2(err, O_CLOEXEC) < 0) {
      send_frame(conn, MSG_ERR, "daemon: pipe2 失败\n", 21);
      send_exit(conn, 1);
      if (out[0] >= 0) {
        close(out[0]);
        close(out[1]);
      }
      if (err[0] >= 0) {
        close(err[0]);
        close(err[1]);
      }
      return;
    }
  }

  auto_free char **av = make_exec_argv(r);
  if (!av) {
    if (is_pty) {
      close(master);
      close(slave);
    } else {
      close(out[0]);
      close(out[1]);
      close(err[0]);
      close(err[1]);
    }
    send_exit(conn, 1);
    return;
  }

  pid_t child = fork();
  if (child < 0) {
    if (is_pty) {
      close(master);
      close(slave);
    } else {
      close(out[0]);
      close(out[1]);
      close(err[0]);
      close(err[1]);
    }
    send_frame(conn, MSG_ERR, "daemon: fork 失败\n", 20);
    send_exit(conn, 1);
    return;
  }

  if (child == 0) {
    close(conn);
    if (is_pty) {
      close(master);
      setsid();
      ioctl(slave, TIOCSCTTY, 0);
      dup2(slave, STDIN_FILENO);
      dup2(slave, STDOUT_FILENO);
      dup2(slave, STDERR_FILENO);
      if (slave > STDERR_FILENO)
        close(slave);
    } else {
      close(out[0]);
      close(err[0]);
      int dn = open("/dev/null", O_RDWR);
      if (dn >= 0) {
        dup2(dn, STDIN_FILENO);
        if (dn > STDERR_FILENO)
          close(dn);
      }
      dup2(out[1], STDOUT_FILENO);
      dup2(err[1], STDERR_FILENO);
      close(out[1]);
      close(err[1]);
    }
    setenv("NO_PROXY", "1", 1);
    signal(SIGHUP, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    reexec(av);
  }

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    if (is_pty) {
      close(master);
      close(slave);
    } else {
      close(out[0]);
      close(out[1]);
      close(err[0]);
      close(err[1]);
    }
    kill(child, SIGTERM);
    waitpid(child, nullptr, 0);
    send_exit(conn, 1);
    return;
  }

  sigset_t ss;
  sigemptyset(&ss);
  sigaddset(&ss, SIGCHLD);
  sigprocmask(SIG_BLOCK, &ss, nullptr);
  int sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);

  struct epoll_event ev, events[8];
  int active_reads = 0;

  if (is_pty) {
    close(slave);
    int fl = fcntl(master, F_GETFL);
    fcntl(master, F_SETFL, fl | O_NONBLOCK);
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = master;
    epoll_ctl(epfd, EPOLL_CTL_ADD, master, &ev);
    active_reads = 1;
  } else {
    close(out[1]);
    close(err[1]);
    out[1] = err[1] = -1;
    fcntl(out[0], F_SETFL, O_NONBLOCK);
    fcntl(err[0], F_SETFL, O_NONBLOCK);
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = out[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, out[0], &ev);
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = err[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, err[0], &ev);
    active_reads = 2;
  }

  if (sfd >= 0) {
    ev.events = EPOLLIN;
    ev.data.fd = sfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
  }

  ev.events = EPOLLHUP | EPOLLERR;
  if (is_pty)
    ev.events |= EPOLLIN;
  ev.data.fd = conn;
  epoll_ctl(epfd, EPOLL_CTL_ADD, conn, &ev);

  int exit_code = EXIT_PENDING;
  int child_done = 0;

  auto_free uint8_t *pty_wbuf = nullptr;
  size_t pty_wbuf_len = 0;
  size_t pty_wbuf_cap = 0;
  bool conn_suspended = false;

  for (;;) {
    int nfds = epoll_wait(epfd, events, 8, -1);
    if (nfds < 0 && errno != EINTR)
      break;

    for (int i = 0; i < nfds; i++) {
      int fd = events[i].data.fd;

      if (sfd >= 0 && fd == sfd) {
        struct signalfd_siginfo si;
        while (read(sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si))) {
          if (!child_done) {
            int st;
            if (waitpid(child, &st, WNOHANG) == child) {
              exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
              child_done = is_pty ? 2 : 1;
            }
          }
        }
      } else if (fd == conn) {
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          kill(child, is_pty ? SIGHUP : SIGTERM);
          waitpid(child, nullptr, 0);
          goto session_end;
        }
        if (is_pty && events[i].events & EPOLLIN) {
          uint8_t type;
          uint32_t mlen;
          if (recv_frame_hdr(conn, &type, &mlen) < 0) {
            kill(child, SIGHUP);
            waitpid(child, nullptr, 0);
            goto session_end;
          }
          if (type == MSG_OUT && mlen > 0 && mlen <= static_cast<uint32_t>(sizeof(buf))) {
            if (read_exact(conn, buf, mlen) == 0) {
              size_t written = 0;
              if (pty_wbuf_len == 0) {
                ssize_t w = write(master, buf, mlen);
                if (w > 0)
                  written = static_cast<size_t>(w);
              }
              size_t rem = mlen - written;
              if (rem > 0) {
                if (pty_wbuf_len + rem <= PTY_WBUF_MAX) {
                  if (pty_wbuf_len + rem > pty_wbuf_cap) {
                    size_t ncap = pty_wbuf_cap ? pty_wbuf_cap : IOBUF;
                    while (ncap < pty_wbuf_len + rem) {
                      if (ncap > PTY_WBUF_MAX / 2) {
                        ncap = PTY_WBUF_MAX;
                        break;
                      }
                      ncap *= 2;
                    }
                    if (ncap > PTY_WBUF_MAX)
                      ncap = PTY_WBUF_MAX;
                    uint8_t *nb = static_cast<uint8_t *>(realloc(pty_wbuf, ncap));
                    if (nb) {
                      pty_wbuf = nb;
                      pty_wbuf_cap = ncap;
                    }
                  }
                  if (pty_wbuf_len + rem <= pty_wbuf_cap) {
                    memcpy(pty_wbuf + pty_wbuf_len, buf + written, rem);
                    pty_wbuf_len += rem;
                    ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
                    ev.data.fd = master;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, master, &ev);
                    if (!conn_suspended && pty_wbuf_len >= PTY_WBUF_HIGH) {
                      ev.events = EPOLLHUP | EPOLLERR;
                      ev.data.fd = conn;
                      epoll_ctl(epfd, EPOLL_CTL_MOD, conn, &ev);
                      conn_suspended = true;
                    }
                  }
                }
              }
            }
          } else if (type == MSG_WINCH && mlen == 4) {
            uint16_t wd[2];
            if (read_exact(conn, wd, 4) == 0) {
              struct winsize nws = {ntohs(wd[0]), ntohs(wd[1]), 0, 0};
              ioctl(master, TIOCSWINSZ, &nws);
              kill(child, SIGWINCH);
            }
          } else {
            uint32_t rem = mlen;
            while (rem) {
              uint32_t c =
                  rem < static_cast<uint32_t>(sizeof(buf)) ? rem : static_cast<uint32_t>(sizeof(buf));
              if (read_exact(conn, buf, c) < 0)
                goto session_end;
              rem -= c;
            }
          }
        }
      } else if (is_pty && fd == master && events[i].events & EPOLLOUT) {
        while (pty_wbuf_len > 0) {
          ssize_t w = write(master, pty_wbuf, pty_wbuf_len);
          if (w > 0) {
            pty_wbuf_len -= static_cast<size_t>(w);
            if (pty_wbuf_len > 0)
              memmove(pty_wbuf, pty_wbuf + w, pty_wbuf_len);
          } else if (w < 0 && errno == EAGAIN) {
            break;
          } else {
            break;
          }
        }
        if (pty_wbuf_len == 0) {
          ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
          ev.data.fd = master;
          epoll_ctl(epfd, EPOLL_CTL_MOD, master, &ev);
        }
        if (conn_suspended && pty_wbuf_len < PTY_WBUF_LOW) {
          ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
          ev.data.fd = conn;
          epoll_ctl(epfd, EPOLL_CTL_MOD, conn, &ev);
          conn_suspended = false;
        }
        if (events[i].events & EPOLLIN) {
          for (;;) {
            ssize_t n = read(master, buf, sizeof(buf));
            if (n > 0) {
              if (send_frame(conn, MSG_OUT, buf, static_cast<uint32_t>(n)) < 0) {
                kill(child, SIGHUP);
                waitpid(child, nullptr, 0);
                goto session_end;
              }
            } else {
              if (errno == EINTR)
                continue;
              break;
            }
          }
        }
      } else {
        if (events[i].events & (EPOLLIN | EPOLLHUP)) {
          bool drained = false;
          for (;;) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
              uint8_t t = fd == err[0] ? MSG_ERR : MSG_OUT;
              if (send_frame(conn, t, buf, static_cast<uint32_t>(n)) < 0) {
                kill(child, is_pty ? SIGHUP : SIGTERM);
                waitpid(child, nullptr, 0);
                goto session_end;
              }
            } else if (n == 0) {
              drained = true;
              break;
            } else {
              if (errno == EINTR)
                continue;
              if (errno == EAGAIN)
                break;
              drained = true;
              break;
            }
          }

          if (drained) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            close(fd);
            if (fd == master)
              master = -1;
            else if (fd == out[0])
              out[0] = -1;
            else if (fd == err[0])
              err[0] = -1;
            if (--active_reads <= 0)
              child_done = 2;
          }
        }
      }
    }

    if (child_done == 1) {
      if (out[0] >= 0)
        drain_fd(out[0], conn, MSG_OUT);
      if (err[0] >= 0)
        drain_fd(err[0], conn, MSG_ERR);
      break;
    } else if (child_done == 2) {
      if (is_pty && master >= 0)
        drain_fd(master, conn, MSG_OUT);
      break;
    }
  }

  if (exit_code == EXIT_PENDING) {
    int st;
    waitpid(child, &st, 0);
    exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
  }

session_end:
  if (sfd >= 0) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, sfd, nullptr);
    close(sfd);
  }
  sigprocmask(SIG_UNBLOCK, &ss, nullptr);
  close(epfd);
  if (master >= 0)
    close(master);
  if (out[0] >= 0)
    close(out[0]);
  if (err[0] >= 0)
    close(err[0]);
  send_exit(conn, exit_code == EXIT_PENDING ? 0 : exit_code);
}

static void handle_conn(const int conn) {
  req_t req;
  if (recv_req(conn, &req) < 0) {
    send_frame(conn, MSG_ERR, "daemon: 无效请求\n", 20);
    send_exit(conn, 1);
    close(conn);
    _exit(1);
  }

  if (req.argc > 0 && strcmp(req.argv[0], "daemon-stop") == 0) {
    const char *msg = "Daemon 正在安全关闭...\n";
    send_frame(conn, MSG_OUT, msg, static_cast<uint32_t>(strlen(msg)));
    send_exit(conn, 0);

    kill(getppid(), SIGTERM);

    free_req(&req);
    close(conn);
    _exit(0);
  }

  for (int i = 0; i < req.argc; i++) {
    if (i > 0 && req.argv[i - 1][0] == '-')
      continue;
    if (strcmp(req.argv[i], "daemon") == 0 ||
        strcmp(req.argv[i], "client") == 0) {
      send_frame(conn, MSG_ERR, "daemon: 拒绝递归调用\n", 31);
      send_exit(conn, 1);
      free_req(&req);
      close(conn);
      _exit(1);
    }
  }

  {
    char cmdline[512];
    size_t off = 0;
    for (int i = 0; i < req.argc && off < sizeof(cmdline) - 1; i++) {
      const int n = snprintf(cmdline + off, sizeof(cmdline) - off, "%s%s",
                       i > 0 ? " " : "", req.argv[i]);
      if (n > 0)
        off += static_cast<size_t>(n);
    }
    log_info("客户端已连接。 模式: %s",
             (req.flags & REQ_FLAG_PTY) ? "PTY" : "PIPE");
    log_info("即将执行: %s", cmdline);
  }

  handle_session(conn, &req);

  log_info("会话已完成。客户端已断开连接。");
  free_req(&req);
  close(conn);
  _exit(0);
}

static void daemonize(const bool foreground) {
  if (!foreground) {
    pid_t pid = fork();
    if (pid < 0)
      exit(1);
    if (pid > 0)
      exit(0);

    if (setsid() < 0)
      exit(1);

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0)
      exit(1);
    if (pid > 0)
      exit(0);
  }

  umask(0);
  if (chdir("/") < 0) {
  }

  if (!foreground) {
    const int dn = open("/dev/null", O_RDONLY);
    if (dn >= 0) {
      dup2(dn, STDIN_FILENO);
      if (dn > STDERR_FILENO)
        close(dn);
    }
  }

  {
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/ds-forkd.log", get_logs_dir());
    safe_strncpy(g_daemon_log_path, log_path, sizeof(g_daemon_log_path));
    rotate_log(log_path, 2 * 1024 * 1024);

    if (!foreground) {
      const int lfd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (lfd >= 0) {
        dup2(lfd, STDOUT_FILENO);
        dup2(lfd, STDERR_FILENO);
        if (lfd > STDERR_FILENO)
          close(lfd);
      }
    } else {
      g_daemon_log_fp = fopen(log_path, "ae");
    }
  }

  oom_protect();
}

static void sigusr2_handler([[maybe_unused]] int sig) {
  g_sigusr2_received = 1;
}

static void sigterm_handler([[maybe_unused]] int sig) {
  g_terminate = 1;
}

int daemon_run(const bool foreground) {
  ensure_runtime();

  if (daemon_probe()) {
    log_error("Daemon 后台服务已在运行中 (@%s)", SOCK_NAME);
    return 1;
  }

  daemonize(foreground);

  {
    const ssize_t n =
        readlink("/proc/self/exe", g_self_path, sizeof(g_self_path) - 1);
    if (n > 0)
      g_self_path[n] = '\0';
    else
      g_self_path[0] = '\0';
  }

  signal(SIGUSR2, sigusr2_handler);

  struct sigaction sa = {};
  sa.sa_handler = sigterm_handler;
  sigaction(SIGTERM, &sa, nullptr);

  auto_close const int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (srv < 0) {
    log_error("daemon socket 建立失败: %s", strerror(errno));
    return 1;
  }

  struct sockaddr_un addr = {};
  const socklen_t alen = make_addr(&addr);
  if (bind(srv, reinterpret_cast<struct sockaddr *>(&addr), alen) < 0) {
    log_error("daemon 绑定失败 (@%s): %s", SOCK_NAME, strerror(errno));
    if (errno == EADDRINUSE) {
      log_info("可能有另一个失效的 " PROJECT_NAME " daemon 残留，请使用 'ps' 检查。");
    }
    return 1;
  }

  if (listen(srv, BACKLOG) < 0) {
    log_error("daemon listen: %s", strerror(errno));
    return 1;
  }

  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  log_info("正在监听 @" SOCK_NAME " (PID %d)", getpid());

  for (;;) {
    rotate_daemon_log_if_needed();

    if (g_sigusr2_received) {
      g_sigusr2_received = 0;
      log_info(
          "探测到二进制文件热更新 (SIGUSR2)。新会话将自动加载新版本的代码执行。");
    }

    auto_close const int conn = accept4(srv, nullptr, nullptr, SOCK_CLOEXEC);

    if (g_terminate) {
      log_info("接收到用户退出指令，Daemon 正在关闭...");
      break;
    }

    if (conn < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      log_error("accept4 错误: %s", strerror(errno));
      continue;
    }

    {
      struct ucred cred;
      socklen_t clen = sizeof(cred);
      if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0) {
        continue;
      }

      if (cred.uid != 0) {
        const char *msg = "权限拒绝：仅允许 Root 用户 (uid 0) 连接通信。";
        send_frame(conn, MSG_ERR, msg, static_cast<uint32_t>(strlen(msg)));
        send_exit(conn, 1);
        continue;
      }
    }

    const pid_t h = fork();
    if (h < 0) {
      continue;
    }
    if (h == 0) {
      // 由于handle_conn中调用_exit
      // auto_exit无法自动清理，所以手动关闭srv
      close(srv);
      signal(SIGCHLD, SIG_DFL);
      handle_conn(conn);
    }
  }
  return 0;
}

bool daemon_probe(void) {
  struct sockaddr_un addr = {};
  const socklen_t alen = make_addr(&addr);
  auto_close const int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0)
    return 0;
  return connect(s, reinterpret_cast<struct sockaddr *>(&addr), alen) == 0;
}
