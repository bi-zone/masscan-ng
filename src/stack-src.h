#ifndef STACK_SOURCE_H
#define STACK_SOURCE_H
#include "massip-addr.h"

/**
 * These the source IP addresses that we'll be spoofing. IP addresses
 * and port numbers come from this list.
 */
struct stack_src_t {
  struct {
    ipv4address_t first;
    ipv4address_t last;
    unsigned range;
  } ipv4;
  struct {
    unsigned first;
    unsigned last;
    unsigned range;
  } port;

  struct {
    ipv6address_t first;
    ipv6address_t last;
    unsigned range;
  } ipv6;
};

int is_myself(const struct stack_src_t *src, const ipaddress *ip,
              unsigned port);
int is_my_ip(const struct stack_src_t *src, const ipaddress *ip);
int is_my_port(const struct stack_src_t *src, unsigned port);

#endif
