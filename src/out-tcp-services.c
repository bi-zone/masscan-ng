#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <netdb.h>
#else
#include <WinSock2.h>
#endif
#include <ctype.h>

#include "out-tcp-services.h"
#include "util-cross.h"
#include "util-malloc.h"

/* This is a stupid hack to avoid dependencies. I want to minimize the
 * dependence on network libraries. For example, I get a warning message on
 * FreeBSD about a missing `htons()`. I could just add a system header, but then
 * this increases dependencies on other things. Alternatively, I could just
 * implement the function myself. So I chose that route. */
static unsigned short my_htons(unsigned port) {
  static const char test[2] = {0x11, 0x22};

#if !defined(_MSC_VER)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

  if (*(unsigned short *)test == 0x1122)
    return (unsigned short)(0xFFFF & port);
  else
    return (unsigned short)((port >> 8) & 0xFF) | ((port & 0xFF) << 8);
#if !defined(_MSC_VER)
#pragma GCC diagnostic pop
#endif
}

static char *tcp_services[COUNT_TCP_PORTS];
static char *udp_services[COUNT_UDP_PORTS];
static char *oproto_services[COUNT_OPROTO_PORTS];

const char *tcp_service_name(int port) {
  if (tcp_services[port])
    return tcp_services[port];

#if defined(__linux__) && !defined(__TERMUX__)
  int r;
  struct servent result_buf;
  struct servent *result;
  char buf[2048];

  r = getservbyport_r(my_htons(port), "tcp", &result_buf, buf, sizeof(buf),
                      &result);

  /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
  if (r != 0 || result == NULL)
    return "unknown";

  return tcp_services[port] = STRDUP(result_buf.s_name);
#else
  {
    struct servent *result;

    result = getservbyport(my_htons((unsigned short)port), "tcp");

    if (result == 0)
      return "unknown";

    return tcp_services[port] = STRDUP(result->s_name);
  }
#endif
}

const char *udp_service_name(int port) {
  if (udp_services[port])
    return udp_services[port];
#if defined(__linux__) && !defined(__TERMUX__)
  int r;
  struct servent result_buf;
  struct servent *result;
  char buf[2048];

  r = getservbyport_r(my_htons(port), "udp", &result_buf, buf, sizeof(buf),
                      &result);

  /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
  if (r != 0 || result == NULL)
    return "unknown";

  return udp_services[port] = STRDUP(result_buf.s_name);
#else
  {
    struct servent *result;

    result = getservbyport(my_htons((unsigned short)port), "udp");

    if (result == 0)
      return "unknown";

    return udp_services[port] = STRDUP(result->s_name);
  }
#endif
}

const char *oproto_service_name(int port) {
  struct protoent *result;

  if (oproto_services[port]) {
    return oproto_services[port];
  }

  result = getprotobynumber(port);
  if (result == 0)
    return "unknown";

  return oproto_services[port] = STRDUP(result->p_name);
}
