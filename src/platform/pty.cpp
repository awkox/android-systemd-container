#include <csignal>
#include <cerrno>
#include <cstring>
#include <format>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include "platform/pty.h"
#include "utils/log.h"

/* 不依赖 /dev/ptmx 符号链接直接打开 master 与 slave。
 * 对于 4.13+ 内核，使用 TIOCGPTPEER 直接从 master 文件描述符派生打开 slave。
 * 对于 3.x 内核，回退使用 TIOCGPTN + 路径打开的方式。*/
int asc_openpty(int &master, int &slave, std::filesystem::path &name) {
  const int m = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (m < 0)
    return -1;

  /* 尽力尝试解锁：部分 4.9 内核魔改后的 devpts mount 可能返回 EINVAL/EIO，忽略错误 */
  int unlock = 0;
  ioctl(m, TIOCSPTLCK, &unlock);

  /* 首选 4.13+ 无路径要求的方法 */
  int s = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (s >= 0) {
    unsigned int ptyno;
    if (ioctl(m, TIOCGPTN, &ptyno) == 0) {
      name = std::format("/dev/pts/{}", ptyno);
    }
  } else {
    /* 回退方案：构建 /dev/pts/N 路径 */
    unsigned int ptyno;
    if (ioctl(m, TIOCGPTN, &ptyno) < 0)
      goto err;
    name = std::filesystem::path("/dev/pts") / std::to_string(ptyno);
    s = open(name.c_str(), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (s < 0)
      goto err;
  }

  master = m;
  slave = s;
  return 0;
err:
  close(m);
  return -1;
}

int terminal_create(tty_info &tty) {
  if (asc_openpty(tty.master, tty.slave, tty.name) < 0) {
    log_error("openpty 获取伪终端失败: {}", strerror(errno));
    return -1;
  }

  /* 修正 PTY 从设备的组属和权限 */
  if (fchown(tty.slave, 0, 5) < 0) {}
  fchmod(tty.slave, 0620);

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

int setup_tios(const int fd, termios &old) {
  if (!isatty(fd) || tcgetattr(fd, &old) < 0)
    return -1;

  // 忽略后台终端读写信号 (原代码逻辑保留)
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  termios new_tios = old;

  // 【核心优化】一行代码调用系统库，完美、标准地清空所有规范模式标志
  cfmakeraw(&new_tios);

  // 追加你特定的定制化需求（防止 \n 被转为 \r\n 破坏容器内 UI 渲染）
  new_tios.c_oflag &= static_cast<tcflag_t>(~(OPOST | ONLCR));
  new_tios.c_cc[VMIN] = 1;
  new_tios.c_cc[VTIME] = 0;

  if (tcsetattr(fd, TCSAFLUSH, &new_tios) < 0)
    return -1;

  return 0;
}