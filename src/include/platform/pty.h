#ifndef ASC_PLATFORM_PTY_H
#define ASC_PLATFORM_PTY_H

#include "common.h"

int openpty(int *master, int *slave, char *name);
int terminal_create(struct tty_info *tty);
int terminal_set_stdfds(const int fd);
int terminal_make_controlling(const int fd);
int setup_tios(const int fd, struct termios *old);

#endif
