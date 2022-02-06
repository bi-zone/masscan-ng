#include "proto-icmp.h"
#include "logger.h"
#include "main-dedup.h"
#include "masscan-status.h"
#include "massip-port.h"
#include "output.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"

/***************************************************************************
 ***************************************************************************/
static int matches_me(struct Output *out, const ipaddress *ip, unsigned port) {
  unsigned i;

  for (i = 0; i < 8; i++) {
    if (is_myself(&out->src[i], ip, port))
      return 1;
  }
  return 0;
}

/***************************************************************************
 ***************************************************************************/
static int parse_port_unreachable(const unsigned char *px, size_t length,
                                  unsigned *r_ip_me, unsigned *r_ip_them,
                                  unsigned *r_port_me, unsigned *r_port_them,
                                  unsigned *r_ip_proto) {
  if (length < 24)
    return -1;
  *r_ip_me = (unsigned)px[12] << 24 | (unsigned)px[13] << 16 |
             (unsigned)px[14] << 8 | (unsigned)px[15];
  *r_ip_them = (unsigned)px[16] << 24 | (unsigned)px[17] << 16 |
               (unsigned)px[18] << 8 | (unsigned)px[19];
  *r_ip_proto = px[9]; /* TCP=6, UDP=17 */

  px += ((size_t)(px[0] & 0xF)) << 2;
  length -= ((size_t)(px[0] & 0xF)) << 2;

  if (length < 4)
    return -1;

  *r_port_me = px[0] << 8 | px[1];
  *r_port_them = px[2] << 8 | px[3];

  return 0;
}

/***************************************************************************
 * This is where we handle all incoming ICMP packets. Some of these packets
 * will be due to scans we are doing, like pings (echoes). Some will
 * be inadvertent, such as "destination unreachable" messages.
 ***************************************************************************/
void handle_icmp(struct Output *out, time_t timestamp, const unsigned char *px,
                 size_t length, struct PreprocessedInfo *parsed,
                 uint64_t entropy) {

  unsigned type = parsed->port_src;
  unsigned code = parsed->port_dst;
  unsigned seqno_me;
  ipaddress ip_me = parsed->dst_ip;
  ipaddress ip_them = parsed->src_ip;
  unsigned cookie;

  seqno_me = (unsigned)px[parsed->transport_offset + 4] << 24 |
             (unsigned)px[parsed->transport_offset + 5] << 16 |
             (unsigned)px[parsed->transport_offset + 6] << 8 |
             (unsigned)px[parsed->transport_offset + 7] << 0;

  switch (type) {
  case 0: /* ICMP echo reply */
  case 129:
    cookie =
        (unsigned)syn_cookie(&ip_them, Templ_ICMP_echo, &ip_me, 0, entropy);
    if ((cookie & 0xFFFFFFFF) != seqno_me)
      return; /* not my response */

    // if (syn_hash(ip_them, Templ_ICMP_echo) != seqno_me)
    //     return; /* not my response */

    /* Report "open" or "existence" of host */
    output_report_status(out, timestamp, PortStatus_Open, &ip_them,
                         1 /* ip proto */, 0, 0, parsed->ip_ttl,
                         parsed->mac_src);
    break;
  case 3: /* destination unreachable */
    switch (code) {
    case 0: /* net unreachable */
      /* We get these a lot while port scanning, often a flood coming
       * back from broken/misconfigured networks */
      break;
    case 1: /* host unreachable */
      /* This means the router doesn't exist */
      break;
    case 2: /* protocol unreachable */
      /* The host exists, but it doesn't support SCTP */
      break;
    case 3: /* port unreachable */
      if (length - parsed->transport_offset > 8) {
        ipaddress ip_me2;
        ipaddress ip_them2;
        unsigned port_me2, port_them2;
        unsigned ip_proto;
        int err;

        ip_me2.version = 4;
        ip_them2.version = 4;

        err = parse_port_unreachable(px + parsed->transport_offset + 8,
                                     length - parsed->transport_offset + 8,
                                     &ip_me2.ipv4, &ip_them2.ipv4, &port_me2,
                                     &port_them2, &ip_proto);

        if (err)
          return;

        if (!matches_me(out, &ip_me2, port_me2))
          return;

        switch (ip_proto) {
        case 6:
        case 17:
        case 132:
          output_report_status(out, timestamp, PortStatus_Closed, &ip_them2,
                               ip_proto, port_them2, 0, parsed->ip_ttl,
                               parsed->mac_src);
          break;
        }
      }
    }
    break;
  default:;
  }
}
