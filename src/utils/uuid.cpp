#include "asc.h"

int generate_uuid(char *buf, const size_t size) {
  if (!buf || size < UUID_LEN + 1)
    return -1;

  unsigned char raw[UUID_LEN / 2];

  auto_close const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    const ssize_t r = read(fd, raw, sizeof(raw));

    if (r == static_cast<ssize_t>(sizeof(raw))) {
      for (int i = 0; i < static_cast<int>(sizeof(raw)); i++)
        snprintf(buf + i * 2, 3, "%02x", raw[i]);

      buf[UUID_LEN] = '\0';
      return 0;
    }
  }

  static bool seeded = false;
  if (!seeded) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    const unsigned int seed =
        static_cast<unsigned int>(ts.tv_nsec ^ ts.tv_sec ^ getpid() ^ getppid());

    srand(seed);
    seeded = true;
  }

  for (int i = 0; i < UUID_LEN / 2; i++)
    raw[i] = static_cast<unsigned char>(rand() & 0xFF);

  for (int i = 0; i < static_cast<int>(sizeof(raw)); i++)
    snprintf(buf + i * 2, 3, "%02x", raw[i]);

  buf[UUID_LEN] = '\0';
  return 0;
}
