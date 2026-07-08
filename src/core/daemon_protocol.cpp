#include "asc.h"

int read_exact(const int fd, void *buf, size_t n) {
  uint8_t *p = static_cast<uint8_t *>(buf);
  while (n) {
    const ssize_t r = read(fd, p, n);
    if (r <= 0)
      return -1;
    p += r;
    n -= static_cast<size_t>(r);
  }
  return 0;
}

int send_frame(const int fd, const uint8_t type, const void *data, const uint32_t len) {
  uint8_t hdr[5];
  const uint32_t nl = htonl(len);
  hdr[0] = type;
  memcpy(hdr + 1, &nl, 4);
  if (write_all(fd, hdr, 5) < 0)
    return -1;
  if (len && write_all(fd, data, len) < 0)
    return -1;
  return 0;
}

int recv_frame_hdr(const int fd, uint8_t *type_out, uint32_t *len_out) {
  uint8_t hdr[5];
  if (read_exact(fd, hdr, 5) < 0)
    return -1;
  *type_out = hdr[0];
  uint32_t nl;
  memcpy(&nl, hdr + 1, 4);
  *len_out = ntohl(nl);
  return 0;
}

void send_exit(const int fd, const int code) {
  const uint32_t nc = htonl(static_cast<uint32_t>(code));
  send_frame(fd, MSG_EXIT, &nc, 4);
}

socklen_t make_addr(struct sockaddr_un *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  const size_t nlen = strlen(SOCK_NAME);
  memcpy(addr->sun_path + 1, SOCK_NAME, nlen);
  return static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1 + nlen);
}

void free_req(req_t *r) {
  for (int i = 0; i < r->argc; i++) {
    if (r->argv[i]) {
      free(r->argv[i]);
      r->argv[i] = nullptr;
    }
  }
}

int recv_req(const int fd, req_t *r) {
  memset(r, 0, sizeof(*r));
  uint32_t nf, na;
  if (read_exact(fd, &nf, 4) < 0 || read_exact(fd, &na, 4) < 0)
    return -1;
  r->flags = ntohl(nf);
  const uint32_t argc = ntohl(na);
  if (!argc || argc > MAX_ARGC)
    return -1;

  for (uint32_t i = 0; i < argc; i++) {
    uint32_t nl;
    if (read_exact(fd, &nl, 4) < 0)
      return -1;
    const uint32_t al = ntohl(nl);
    if (al > MAX_ARG)
      return -1;
    r->argv[i] = static_cast<char *>(malloc(static_cast<size_t>(al) + 1));
    if (!r->argv[i])
      return -1;
    if (al && read_exact(fd, r->argv[i], al) < 0)
      return -1;
    r->argv[i][al] = '\0';
    r->argc++;
  }
  r->argv[r->argc] = nullptr;

  if (r->flags & REQ_FLAG_PTY) {
    uint16_t ws[2];
    if (read_exact(fd, ws, 4) < 0)
      return -1;
    r->rows = ntohs(ws[0]);
    r->cols = ntohs(ws[1]);
    if (!r->rows)
      r->rows = 24;
    if (!r->cols)
      r->cols = 80;
  }
  return 0;
}
