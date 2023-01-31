#include "logger.h"
#include "masscan.h"
#include "output.h"
#include "pixie-sockets.h"

#include <assert.h>
#include <ctype.h>

/****************************************************************************
 * Receive a full line from the socket
 ****************************************************************************/
static size_t recv_line(SOCKET fd, void *buf, size_t buf_size) {
  size_t count = 0;

  while (count < buf_size) {
    size_t bytes_received;

    bytes_received = recv(fd, (char *)buf + count, 1, 0);
    if (bytes_received == 0) {
      LOG(LEVEL_ERROR, "redis: recv_line() failed\n");
      exit(1);
    }
    count++;
    if (((unsigned char *)buf)[count - 1] == '\n')
      break;
  }

  return count;
}

/****************************************************************************
 ****************************************************************************/
static int parse_state_machine(struct Output *out, const unsigned char *px,
                               size_t length) {

  size_t state = out->redis.state;
  size_t i;

  enum { START, NUMBER, P, PO, PON, PONG, PONG_CR, PONG_CR_LF };

  for (i = 0; i < length; i++) {
    switch (state) {
    case START:
      switch (px[i]) {
      case '+':
        state = P;
        break;
      case ':':
        state = NUMBER;
        break;
      default:
        LOG(LEVEL_ERROR, "redis: unexpected data: %.*s\n", (int)(length - i),
            px + i);
        exit(1);
      }
      break;
    case NUMBER:
      if (isdigit(px[i]) || px[i] == '\r') {
        // pass
      } else if (px[i] == '\n') {
        state = START;
        if (out->redis.outstanding == 0) {
          LOG(LEVEL_ERROR, "redis: out of sync\n");
          exit(1);
        }
        out->redis.outstanding--;
      } else {
        LOG(LEVEL_ERROR, "redis: unexpected data: %.*s\n", (int)(length - i),
            px + i);
        exit(1);
      }
      break;
    case P:
    case PO:
    case PON:
    case PONG_CR:
    case PONG_CR_LF:
      if ("PONG+\r\n"[state - P] == px[i]) {
        state++;
        if (px[i] == '\n') {
          out->redis.state = START;
          return 1;
        }
      } else {
        LOG(LEVEL_ERROR, "redis: unexpected data: %.*s\n", (int)(length - i),
            px + i);
        exit(1);
      }
      break;
    default:
      LOG(LEVEL_ERROR, "redis: unexpected state: %" PRIuPTR "\n", state);
      exit(1);
    }
  }
  out->redis.state = state;
  return 0;
}

/****************************************************************************
 ****************************************************************************/
static int clean_response_queue(struct Output *out, SOCKET fd) {
  fd_set readfds;
  struct timeval tv = {0, 0};
  int x;
  int nfds;
  unsigned char buf[1024];
  size_t bytes_read;

  FD_ZERO(&readfds);
#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif
  FD_SET(fd, &readfds);
  nfds = (int)fd;

  x = select(nfds, &readfds, 0, 0, &tv);
  if (x == 0)
    return 1;
  if (x < 0) {
    LOG(LEVEL_ERROR, "redis:select() failed\n");
    exit(1);
  }
  if (x != 1) {
    LOG(LEVEL_ERROR, "redis:select() failed\n");
    exit(1);
  }

  /* Data exists, so parse it */
  bytes_read = recv(fd, (char *)buf, sizeof(buf), 0);
  if (bytes_read == 0) {
    LOG(LEVEL_ERROR, "redis:recv() failed\n");
    exit(1);
  }

  return parse_state_machine(out, buf, bytes_read);
}

/****************************************************************************
 ****************************************************************************/
static void redis_out_open(struct Output *out) {
  ptrdiff_t fd = out->redis.fd;
  size_t count;
  unsigned char line[1024];

  count = send((SOCKET)fd, "PING\r\n", 6, 0);
  if (count != 6) {
    LOG(LEVEL_ERROR, "redis: send(ping) failed\n");
    exit(1);
  }

  count = recv_line((SOCKET)fd, line, sizeof(line));
  if (count != 7 && memcmp(line, "+PONG\r\n", 7) != 0) {
    LOG(LEVEL_ERROR, "redis: unexpected response from redis server: %s\n",
        line);
    exit(1);
  }
}

/****************************************************************************
 ****************************************************************************/
static void redis_out_close(struct Output *out) {
  ptrdiff_t fd = out->redis.fd;
  size_t count;
  unsigned char line[1024];

  count = send((SOCKET)fd, "QUIT\r\n", 6, 0);
  if (count != 6) {
    LOG(LEVEL_ERROR, "redis: send(quit) failed\n");
    exit(1);
  }

  count = recv_line((SOCKET)fd, line, sizeof(line));
  if ((count != 5 && memcmp(line, "+OK\r\n", 5) != 0) &&
      (count != 4 && memcmp(line, ":0\r\n", 4) != 0)) {
    LOG(LEVEL_ERROR, "redis: unexpected response from redis server: %s\n",
        line);
    exit(1);
  }
}

/****************************************************************************
 ****************************************************************************/
static void redis_out_status(struct Output *out, time_t timestamp,
                             enum PortStatus status, const ipaddress *ip,
                             unsigned ip_proto, unsigned port, unsigned reason,
                             unsigned ttl) {

  ptrdiff_t fd = out->redis.fd;
  char line[1024];
  int line_length;
  char ip_string[64];
  char port_string[10];
  int ip_string_length;
  int port_string_length;
  size_t count;
  char values[64];
  int values_length;
  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);

  ip_string_length = sprintf_s(ip_string, sizeof(ip_string), "%s", fmt.string);
  port_string_length = sprintf_s(port_string, sizeof(port_string), "%u/%s",
                                 port, name_from_ip_proto(ip_proto));

  /**3
  $3
  SET
  $5
  mykey
  $7
  myvalue
  */

  /* KEY: "host"
   * VALUE: ip */
  sprintf_s(line, sizeof(line),
            "*3\r\n"
            "$4\r\nSADD\r\n"
            "$%d\r\n%s\r\n"
            "$%d\r\n%s\r\n",
            4, "host", ip_string_length, ip_string);

  count = send((SOCKET)fd, line, (int)strlen(line), 0);
  if (count != strlen(line)) {
    LOG(LEVEL_ERROR, "redis: error sending data\n");
    exit(1);
  }
  out->redis.outstanding++;

  /* KEY: ip
   * VALUE: port */
  sprintf_s(line, sizeof(line),
            "*3\r\n"
            "$4\r\nSADD\r\n"
            "$%d\r\n%s\r\n"
            "$%d\r\n%s\r\n",
            ip_string_length, ip_string, port_string_length, port_string);

  count = send((SOCKET)fd, line, (int)strlen(line), 0);
  if (count != strlen(line)) {
    LOG(LEVEL_ERROR, "redis: error sending data\n");
    exit(1);
  }
  out->redis.outstanding++;

  /* KEY: ip:port
   * VALUE: timestamp:status:reason:ttl */
  values_length = sprintf_s(values, sizeof(values), "%" PRIu64 ":%u:%u:%u",
                            (uint64_t)timestamp, (unsigned)status, reason, ttl);
  line_length = sprintf_s(line, sizeof(line),
                          "*3\r\n"
                          "$4\r\nSADD\r\n"
                          "$%d\r\n%s:%s\r\n"
                          "$%d\r\n%s\r\n",
                          ip_string_length + 1 + port_string_length, ip_string,
                          port_string, values_length, values);
  count = send((SOCKET)fd, line, line_length, 0);
  if (count != (size_t)line_length) {
    LOG(LEVEL_ERROR, "redis: error sending data\n");
    exit(1);
  }
  out->redis.outstanding++;

  clean_response_queue(out, (SOCKET)fd);
}

/****************************************************************************
 ****************************************************************************/
static void redis_out_banner(struct Output *out, time_t timestamp,
                             const ipaddress *ip, unsigned ip_proto,
                             unsigned port, enum ApplicationProtocol proto,
                             unsigned ttl, const unsigned char *px,
                             size_t length) {

  UNUSEDPARM(ttl);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(out);
  UNUSEDPARM(ip);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(port);
  UNUSEDPARM(proto);
  UNUSEDPARM(px);
  UNUSEDPARM(length);
}

static void redis_out_sign(struct Output *out, time_t timestamp,
                           const ipaddress *ip, unsigned ip_proto,
                           unsigned port, enum ApplicationProtocol proto) {

  UNUSEDPARM(timestamp);
  UNUSEDPARM(out);
  UNUSEDPARM(ip);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(port);
  UNUSEDPARM(proto);
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType redis_output = {"redis",          NULL,
                                        redis_out_open,   redis_out_close,
                                        redis_out_status, redis_out_banner,
                                        redis_out_sign};
