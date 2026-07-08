#ifndef ASC_CORE_DAEMON_H
#define ASC_CORE_DAEMON_H

#include "common.h"

int daemon_run(const bool foreground);
bool daemon_probe(void);
int client_run(int argc, char **argv);

#endif
