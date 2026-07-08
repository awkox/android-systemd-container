#ifndef ASC_CORE_DAEMON_H
#define ASC_CORE_DAEMON_H

int daemon_run(const bool foreground);
bool daemon_probe();
int client_run(int argc, char **argv);

#endif
