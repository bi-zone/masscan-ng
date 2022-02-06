#ifndef SYN_COOKIE_H
#define SYN_COOKIE_H
#include "massip-addr.h"
#include <stdint.h>

/* Create a hash of the src/dst IP/port combination. This allows us to match
 * incoming responses with their original requests */
uint64_t syn_cookie_ipv4(const ipv4address_t *ip_dst, unsigned port_dst,
                         const ipv4address_t *ip_src, unsigned port_src,
                         uint64_t entropy);

uint64_t syn_cookie(const ipaddress *ip_dst, unsigned port_dst,
                    const ipaddress *ip_src, unsigned port_src,
                    uint64_t entropy);

uint64_t syn_cookie_ipv6(const ipv6address_t *ip_dst, unsigned port_dst,
                         const ipv6address_t *ip_src, unsigned port_src,
                         uint64_t entropy);

/* Called on startup to set a secret key */
uint64_t get_entropy(void);

#endif
