#ifndef ASC_PLATFORM_PTY_H
#define ASC_PLATFORM_PTY_H

#include "common.h"

int asc_openpty(int *master, int *slave, fs::path *name);
int terminal_create(tty_info *tty);
int terminal_set_stdfds(const int fd);
int setup_tios(const int fd, termios *old);

#endif
