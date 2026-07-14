#include "asc.h"

int get_kernel_version(int *major, int *minor) {
  utsname uts;
  if (uname(&uts) < 0)
    return -1;

  if (sscanf(uts.release, "%d.%d", major, minor) != 2)
    return -1;

  return 0;
}

void oom_protect(void) {
  FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f) {
    fprintf(f, "-1000\n");
    fclose(f);
  }
}
