#ifndef ASC_CLEANUP_H
#define ASC_CLEANUP_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 * Cleanup attribute helpers (RAII-style automatic resource management)
 *
 * Usage:
 *   auto_free char *buf = malloc(1024);    // auto-free on scope exit
 *   auto_fclose FILE *f = fopen(...);      // auto-fclose on scope exit
 *   auto_close int fd = open(...);          // auto-close on scope exit
 *   auto_closedir DIR *d = opendir(...);    // auto-closedir on scope exit
 * ---------------------------------------------------------------------------*/
[[maybe_unused]] static void cfree(void *p) {
  void **pp = p;
  if (*pp) {
    free(*pp);
    *pp = nullptr;
  }
}

[[maybe_unused]] static void cfclose(FILE **f) {
  if (*f) fclose(*f);
}

[[maybe_unused]] static void cclose(const int *fd) {
  if (*fd >= 0) close(*fd);
}

[[maybe_unused]] static void cclosedir(DIR **d) {
  if (*d) closedir(*d);
}

#define _cleanup_(x)  [[gnu::cleanup(x)]]
#define auto_free     _cleanup_(cfree)
#define auto_fclose   _cleanup_(cfclose)
#define auto_close    _cleanup_(cclose)
#define auto_closedir _cleanup_(cclosedir)

#endif
