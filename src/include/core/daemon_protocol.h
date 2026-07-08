#ifndef ASC_CORE_DAEMON_PROTOCOL_H
#define ASC_CORE_DAEMON_PROTOCOL_H

#include "common.h"

#define SOCK_NAME PROJECT_NAME
#define BACKLOG SOMAXCONN
#define MAX_ARGC 64
#define MAX_ARG 8192
#define IOBUF 8192

constexpr size_t PTY_WBUF_MAX = (256 * 1024);
constexpr size_t PTY_WBUF_HIGH = (192 * 1024);
constexpr size_t PTY_WBUF_LOW = (64 * 1024);

constexpr uint8_t MSG_OUT = 0x01;
constexpr uint8_t MSG_ERR = 0x02;
constexpr uint8_t MSG_WINCH = 0x03;
constexpr uint8_t MSG_EXIT = 0xFF;

#define REQ_FLAG_PTY (1u << 0)
#define EXIT_PENDING (-1)

typedef struct {
  uint32_t flags;
  int argc;
  char *argv[MAX_ARGC + 1];
  uint16_t rows, cols;
} req_t;

int read_exact(const int fd, void *buf, size_t n);
int send_frame(const int fd, const uint8_t type, const void *data, const uint32_t len);
int recv_frame_hdr(const int fd, uint8_t *type_out, uint32_t *len_out);
void send_exit(const int fd, const int code);
socklen_t make_addr(struct sockaddr_un *addr);
void free_req(req_t *r);
int recv_req(const int fd, req_t *r);

#endif
