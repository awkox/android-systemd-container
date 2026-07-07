#include "asc.h"

/* 不依赖 /dev/ptmx 符号链接直接打开 master 与 slave。
 * 对于 4.13+ 内核，使用 TIOCGPTPEER 直接从 master 文件描述符派生打开 slave。
 * 对于 3.x 内核，回退使用 TIOCGPTN + 路径打开的方式。*/
int openpty(int *master, int *slave, char *name) {
  const int m = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (m < 0)
    return -1;

  /* 尽力尝试解锁：部分 4.9 内核魔改后的 devpts mount 可能返回 EINVAL/EIO，忽略错误 */
  int unlock = 0;
  ioctl(m, TIOCSPTLCK, &unlock);

  /* 首选 4.13+ 无路径要求的方法 */
  int s = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (s >= 0) {
    if (name) {
      unsigned int ptyno;
      if (ioctl(m, TIOCGPTN, &ptyno) == 0) {
        snprintf(name, PATH_MAX, "/dev/pts/%u", ptyno);
      }
    }
  } else {
    /* 回退方案：构建 /dev/pts/N 路径 */
    unsigned int ptyno;
    if (ioctl(m, TIOCGPTN, &ptyno) < 0)
      goto err;
    char pts_path[PATH_MAX];
    snprintf(pts_path, PATH_MAX, "/dev/pts/%u", ptyno);
    if (name)
      snprintf(name, PATH_MAX, "%s", pts_path);
    s = open(pts_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (s < 0)
      goto err;
  }

  *master = m;
  *slave = s;
  return 0;
err:
  close(m);
  return -1;
}

int terminal_create(struct tty_info *tty) {
  if (openpty(&tty->master, &tty->slave, tty->name) < 0) {
    log_error("openpty 获取伪终端失败: %s", strerror(errno));
    return -1;
  }

  /* 修正 PTY 从设备的组属和权限 */
  if (fchown(tty->slave, 0, 5) < 0) {}
  fchmod(tty->slave, 0620);

  return 0;
}

int terminal_set_stdfds(const int fd) {
  if (dup2(fd, STDIN_FILENO) < 0)
    return -1;
  if (dup2(fd, STDOUT_FILENO) < 0)
    return -1;
  if (dup2(fd, STDERR_FILENO) < 0)
    return -1;
  return 0;
}

int terminal_make_controlling(const int fd) {
  setsid();

  if (ioctl(fd, TIOCSCTTY, nullptr) < 0) {
    log_error("TIOCSCTTY 控制终端绑定失败: %s", strerror(errno));
    return -1;
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * Termios 终端设置
 * ---------------------------------------------------------------------------*/

int setup_tios(const int fd, struct termios *old) {
  struct termios new_tios;

  if (!isatty(fd))
    return -1;

  if (tcgetattr(fd, old) < 0)
    return -1;

  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  new_tios = *old;

  /* Raw 模式 - 尽可能对齐 LXC/SSH 的设置以保证最大兼容性 */
  new_tios.c_iflag |= IGNPAR;
  new_tios.c_iflag &=
      static_cast<tcflag_t>(~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF));
#ifdef IUCLC
  new_tios.c_iflag &= static_cast<tcflag_t>(~IUCLC);
#endif
  new_tios.c_lflag &=
      static_cast<tcflag_t>(~(TOSTOP | ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL));
#ifdef IEXTEN
  new_tios.c_lflag &= static_cast<tcflag_t>(~IEXTEN);
#endif
  /* 禁用输出处理：如果主 PTY 的 OPOST 处于 ONLCR 激活状态，\n 会被转换为 \r\n，
   * 从而破坏 tmux、vim 等终端 UI 工具的转义序列。在沙盒从 PTY 内它会自行设置，所以
   * 在此必须禁用以保证只转换一次。 */
  new_tios.c_oflag &= static_cast<tcflag_t>(~(OPOST | ONLCR));
  new_tios.c_cc[VMIN] = 1;
  new_tios.c_cc[VTIME] = 0;

  if (tcsetattr(fd, TCSAFLUSH, &new_tios) < 0)
    return -1;

  return 0;
}