/*
    Construct a TCP packet based upon a template.

    The (eventual) idea of this module is to make this scanner extensible
    by providing an arbitrary packet template. Thus, the of this module
    is to take an existing packet template, parse it, then make
    appropriate changes.
*/

#include <assert.h>

#include "logger.h"
#include "massip-port.h"
#include "pixie-timer.h"
#include "proto-preprocess.h"
#include "proto-sctp.h"
#include "string_s.h"
#include "stub-pcap-dlt.h" /* data link types, like NULL, RAW, or ETHERNET */
#include "syn-cookie.h"
#include "templ-payloads.h"
#include "templ-pkt.h"
#include "util-checksum.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "vulncheck.h"

static unsigned char default_tcp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x2c" /* total length = 44 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x06" /* TTL=255, proto=TCP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\0\0"             /* source port */
    "\0\0"             /* destination port */
    "\0\0\0\0"         /* sequence number */
    "\0\0\0\0"         /* ACK number */
    "\x60"             /* header length */
    "\x02"             /* SYN */
    "\x04\x0"          /* window fixed to 1024 */
    "\xFF\xFF"         /* checksum */
    "\x00\x00"         /* urgent pointer */
    "\x02\x04\x05\xb4" /* added options [mss 1460] */
    ;

static unsigned char default_udp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x1c" /* total length = 28 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x11" /* TTL=255, proto=UDP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\xfe\xdc" /* source port */
    "\x00\x00" /* destination port */
    "\x00\x08" /* length */
    "\x00\x00" /* checksum */
    ;

static unsigned char default_sctp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x34" /* total length = 52 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x84" /* TTL=255, proto = SCTP */
    "\x00\x00" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x00\x00"         /* source port */
    "\x00\x00"         /* destination port */
    "\x00\x00\x00\x00" /* verification tag */
    "\x58\xe4\x5d\x36" /* checksum */
    "\x01"             /* type = init */
    "\x00"             /* flags = none */
    "\x00\x14"         /* length = 20 */
    "\x9e\x8d\x52\x25" /* initiate tag */
    "\x00\x00\x80\x00" /* receiver window credit */
    "\x00\x0a"         /* outbound streams = 10 */
    "\x08\x00"         /* inbound streams = 2048 */
    "\x46\x1a\xdf\x3d" /* initial TSN */
    ;

static unsigned char default_icmp_ping_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x4c" /* total length = 76 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x01" /* TTL=255, proto=ICMP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x08\x00" /* Ping Request */
    "\x00\x00" /* checksum */

    "\x00\x00\x00\x00" /* ID, seqno */

    "\x08\x09\x0a\x0b" /* payload */
    "\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13"
    "\x14\x15\x16\x17"
    "\x18\x19\x1a\x1b"
    "\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23"
    "\x24\x25\x26\x27"
    "\x28\x29\x2a\x2b"
    "\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33"
    "\x34\x35\x36\x37";

static unsigned char default_icmp_timestamp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x28" /* total length = 84 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x01" /* TTL=255, proto=UDP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x0d\x00" /* timestamp request */
    "\x00\x00" /* checksum */
    "\x00\x00" /* identifier */
    "\x00\x00" /* sequence number */
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00";

static unsigned char default_arp_template[] =
    "\xff\xff\xff\xff\xff\xff" /* Ethernet: destination */
    "\x00\x00\x00\x00\x00\x00" /* Ethernet: source */
    "\x08\x06"                 /* Ethernet type: ARP */
    "\x00\x01"                 /* hardware = Ethernet */
    "\x08\x00"                 /* protocol = IPv4 */
    "\x06\x04"                 /* MAC length = 6, IPv4 length = 4 */
    "\x00\x01"                 /* opcode = request */

    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00"

    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00";

/***************************************************************************
 * Checksum the IP header. This is a "partial" checksum, so we
 * don't reverse the bits ~.
 ***************************************************************************/
static unsigned ip_header_checksum(const unsigned char *px, size_t offset,
                                   size_t max_offset) {

  size_t header_length = (size_t)(px[offset] & 0xF) * 4;
  unsigned xsum = 0;
  size_t i;

  /* restrict check only over packet */
  if (max_offset > offset + header_length)
    max_offset = offset + header_length;

  /* add all the two-byte words together */
  xsum = 0;
  for (i = offset; i < max_offset; i += 2) {
    xsum += px[i] << 8 | px[i + 1];
  }

  /* if more than 16 bits in result, reduce to 16 bits */
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);

  return xsum;
}

/***************************************************************************
 ***************************************************************************/
static unsigned tcp_checksum2(const unsigned char *px, size_t offset_ip,
                              size_t offset_tcp, size_t tcp_length) {

  uint64_t xsum = 0;
  size_t i;

  /* pseudo checksum */
  xsum = 6;
  xsum += tcp_length;
  xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
  xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
  xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
  xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

  /* TCP checksum */
  for (i = 0; i < tcp_length; i += 2) {
    xsum += px[offset_tcp + i] << 8 | px[offset_tcp + i + 1];
  }

  xsum -= (tcp_length & 1) *
          px[offset_tcp + i -
             1]; /* yea I know going off end of packet is bad so sue me */
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);

  return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
static unsigned tcp_ipv4_checksum(struct TemplatePacket *tmpl) {
  const unsigned char *px = tmpl->ipv4.packet;
  size_t offset_ip = tmpl->ipv4.offset_ip;
  size_t offset_app = tmpl->ipv4.offset_app;
  size_t offset_tcp = tmpl->ipv4.offset_tcp;
  unsigned xsum = 0;
  size_t i;

  /* pseudo checksum */
  xsum = 6;
  xsum += (unsigned)(offset_app - offset_tcp);
  xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
  xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
  xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
  xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

  /* TCP checksum */
  for (i = offset_tcp; i < offset_app; i += 2) {
    xsum += px[i] << 8 | px[i + 1];
  }
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);

  return xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned udp_checksum2(const unsigned char *px, size_t offset_ip,
                       size_t offset_tcp, size_t tcp_length) {

  uint64_t xsum = 0;
  size_t i;

  /* pseudo checksum */
  xsum = 17;
  xsum += tcp_length;
  xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
  xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
  xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
  xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

  /* TCP checksum */
  for (i = 0; i < tcp_length; i += 2) {
    xsum += px[offset_tcp + i] << 8 | px[offset_tcp + i + 1];
  }

  xsum -= (tcp_length & 1) *
          px[offset_tcp + i -
             1]; /* yea I know going off end of packet is bad so sue me */
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);

  return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
static unsigned udp_ipv4_checksum(struct TemplatePacket *tmpl) {
  return udp_checksum2(tmpl->ipv4.packet, tmpl->ipv4.offset_ip,
                       tmpl->ipv4.offset_tcp,
                       tmpl->ipv4.length - tmpl->ipv4.offset_tcp);
}

/***************************************************************************
 ***************************************************************************/
static unsigned icmp_checksum2(const unsigned char *px, size_t offset_icmp,
                               size_t icmp_length) {

  uint64_t xsum = 0;
  size_t i;

  for (i = 0; i < icmp_length; i += 2) {
    xsum += px[offset_icmp + i] << 8 | px[offset_icmp + i + 1];
  }

  xsum -= (icmp_length & 1) *
          px[offset_icmp + i -
             1]; /* yea I know going off end of packet is bad so sue me */
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);
  xsum = (xsum & 0xFFFF) + (xsum >> 16);

  return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
static unsigned icmp_ipv4_checksum(struct TemplatePacket *tmpl) {
  return icmp_checksum2(tmpl->ipv4.packet, tmpl->ipv4.offset_tcp,
                        tmpl->ipv4.length - tmpl->ipv4.offset_tcp);
}

/***************************************************************************
 ***************************************************************************/

struct TemplateSet *templ_copy(struct TemplateSet *templset_dst,
                               const struct TemplateSet *templset_src) {

  size_t i;
  memcpy(templset_dst, templset_src, sizeof(struct TemplateSet));
  for (i = 0; i < templset_src->count; i++) {
    const struct TemplatePacket *p1 = &templset_src->pkts[i];
    struct TemplatePacket *p2 = &templset_dst->pkts[i];
    p2->ipv4.packet = MALLOC(p2->ipv4.length);
    memcpy(p2->ipv4.packet, p1->ipv4.packet, p2->ipv4.length);

    // if not arp
    if (p1->ipv6.packet != NULL) {
      p2->ipv6.packet = MALLOC(p2->ipv6.length);
      memcpy(p2->ipv6.packet, p1->ipv6.packet, p2->ipv6.length);
    }
  }

  return templset_dst;
}

/***************************************************************************
 ***************************************************************************/
void tcp_set_window(unsigned char *px, size_t px_length, unsigned window) {

  struct PreprocessedInfo parsed;
  unsigned x;
  size_t offset;
  unsigned xsum;

  /* Parse the frame looking for the TCP header */
  x = preprocess_frame(px, px_length, 1 /*enet*/, &parsed);
  if (!x || parsed.found == FOUND_NOTHING)
    return;
  if (parsed.ip_protocol != 6)
    return;
  offset = parsed.transport_offset;
  if (offset + 20 > px_length)
    return;

    /* set the new window */
#if 0
    xsum = px[offset + 16] << 8 | px[offset + 17];
    xsum = (~xsum)&0xFFFF;
    xsum += window & 0xFFFF;
    xsum -= px[offset + 14] << 8 | px[offset + 15];
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = (~xsum)&0xFFFF;
#endif

  px[offset + 14] = (unsigned char)(window >> 8);
  px[offset + 15] = (unsigned char)(window >> 0);
  px[offset + 16] = (unsigned char)(0);
  px[offset + 17] = (unsigned char)(0);

  xsum = ~tcp_checksum2(px, parsed.ip_offset, parsed.transport_offset,
                        parsed.transport_length);

  px[offset + 16] = (unsigned char)(xsum >> 8);
  px[offset + 17] = (unsigned char)(xsum >> 0);
}

/***************************************************************************
 ***************************************************************************/
size_t tcp_create_packet(struct TemplatePacket *tmpl, const ipaddress *ip_them,
                         unsigned port_them, const ipaddress *ip_me,
                         unsigned port_me, unsigned seqno, unsigned ackno,
                         unsigned flags, const unsigned char *payload,
                         size_t payload_length, unsigned char *px,
                         size_t px_length) {
  uint64_t xsum;

  if (ip_them->version == 4) {
    unsigned ip_id = ip_them->ipv4 ^ port_them ^ seqno;
    size_t offset_ip = tmpl->ipv4.offset_ip;
    size_t offset_tcp = tmpl->ipv4.offset_tcp;
    size_t offset_app = tmpl->ipv6.offset_app;
    size_t new_length = offset_app + payload_length;
    size_t ip_len = (offset_app - offset_ip) + payload_length;

    if (new_length > px_length) {
      LOG(LEVEL_WARNING, "tcp: err generating packet: too much payload\n");
      return 0;
    }

    memcpy(px + 0, tmpl->ipv4.packet, tmpl->ipv4.length);
    if (payload != NULL && payload_length != 0) {
      memcpy(px + offset_app, payload, payload_length);
    }

    /* Fill in the empty fields in the IP header and then re-calculate
     * the checksum. */
    px[offset_ip + 2] = (unsigned char)(ip_len >> 8);
    px[offset_ip + 3] = (unsigned char)(ip_len & 0xFF);
    px[offset_ip + 4] = (unsigned char)(ip_id >> 8);
    px[offset_ip + 5] = (unsigned char)(ip_id & 0xFF);
    px[offset_ip + 12] = (unsigned char)((ip_me->ipv4 >> 24) & 0xFF);
    px[offset_ip + 13] = (unsigned char)((ip_me->ipv4 >> 16) & 0xFF);
    px[offset_ip + 14] = (unsigned char)((ip_me->ipv4 >> 8) & 0xFF);
    px[offset_ip + 15] = (unsigned char)((ip_me->ipv4 >> 0) & 0xFF);
    px[offset_ip + 16] = (unsigned char)((ip_them->ipv4 >> 24) & 0xFF);
    px[offset_ip + 17] = (unsigned char)((ip_them->ipv4 >> 16) & 0xFF);
    px[offset_ip + 18] = (unsigned char)((ip_them->ipv4 >> 8) & 0xFF);
    px[offset_ip + 19] = (unsigned char)((ip_them->ipv4 >> 0) & 0xFF);

    px[offset_ip + 10] = (unsigned char)(0);
    px[offset_ip + 11] = (unsigned char)(0);

    xsum = (unsigned)~ip_header_checksum(px, offset_ip, px_length);

    px[offset_ip + 10] = (unsigned char)(xsum >> 8);
    px[offset_ip + 11] = (unsigned char)(xsum & 0xFF);

    /* now do the same for TCP */
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);

    px[offset_tcp + 8] = (unsigned char)(ackno >> 24);
    px[offset_tcp + 9] = (unsigned char)(ackno >> 16);
    px[offset_tcp + 10] = (unsigned char)(ackno >> 8);
    px[offset_tcp + 11] = (unsigned char)(ackno >> 0);

    px[offset_tcp + 13] = (unsigned char)flags;

    px[offset_tcp + 14] = (unsigned char)(1200 >> 8);
    px[offset_tcp + 15] = (unsigned char)(1200 & 0xFF);

    px[offset_tcp + 16] = (unsigned char)0;
    px[offset_tcp + 17] = (unsigned char)0;

    xsum = tcp_checksum2(px, tmpl->ipv4.offset_ip, tmpl->ipv4.offset_tcp,
                         new_length - tmpl->ipv4.offset_tcp);
    xsum = ~xsum;

    px[offset_tcp + 16] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 17] = (unsigned char)(xsum >> 0);

    if (new_length < 60) {
      memset(px + new_length, 0, 60 - new_length);
      new_length = 60;
    }
    return new_length;
  } else {
    size_t offset_ip = tmpl->ipv6.offset_ip;
    size_t offset_tcp = tmpl->ipv6.offset_tcp;
    size_t offset_app = tmpl->ipv6.offset_app;

    /* Make sure the new packet won't exceed buffer size */
    if (offset_app + payload_length > px_length) {
      LOG(LEVEL_WARNING, "tcp: err generating packet: too much payload\n");
      return 0;
    }

    /* Copy over everything up to the new application-layer-payload */
    memcpy(px, tmpl->ipv6.packet, tmpl->ipv6.offset_app);

    /* Replace the template's application-layer-payload with the new app-payload
     */
    if (payload != NULL && payload_length != 0) {
      memcpy(px + tmpl->ipv6.offset_app, payload, payload_length);
    }

    /* Fixup the "payload length" field in the IPv6 header. This is everything
     * after the IPv6 header. There may be additional headers between the IPv6
     * and TCP headers, so the calculation isn't simply the length of the TCP
     * portion */
    {
      size_t len =
          tmpl->ipv6.offset_app + payload_length - tmpl->ipv6.offset_ip - 40;
      px[offset_ip + 4] = (unsigned char)(len >> 8) & 0xFF;
      px[offset_ip + 5] = (unsigned char)(len >> 0) & 0xFF;
    }

    /* Copy over the IP addresses */
    px[offset_ip + 8] = (unsigned char)((ip_me->ipv6.hi >> 56ULL) & 0xFF);
    px[offset_ip + 9] = (unsigned char)((ip_me->ipv6.hi >> 48ULL) & 0xFF);
    px[offset_ip + 10] = (unsigned char)((ip_me->ipv6.hi >> 40ULL) & 0xFF);
    px[offset_ip + 11] = (unsigned char)((ip_me->ipv6.hi >> 32ULL) & 0xFF);
    px[offset_ip + 12] = (unsigned char)((ip_me->ipv6.hi >> 24ULL) & 0xFF);
    px[offset_ip + 13] = (unsigned char)((ip_me->ipv6.hi >> 16ULL) & 0xFF);
    px[offset_ip + 14] = (unsigned char)((ip_me->ipv6.hi >> 8ULL) & 0xFF);
    px[offset_ip + 15] = (unsigned char)((ip_me->ipv6.hi >> 0ULL) & 0xFF);

    px[offset_ip + 16] = (unsigned char)((ip_me->ipv6.lo >> 56ULL) & 0xFF);
    px[offset_ip + 17] = (unsigned char)((ip_me->ipv6.lo >> 48ULL) & 0xFF);
    px[offset_ip + 18] = (unsigned char)((ip_me->ipv6.lo >> 40ULL) & 0xFF);
    px[offset_ip + 19] = (unsigned char)((ip_me->ipv6.lo >> 32ULL) & 0xFF);
    px[offset_ip + 20] = (unsigned char)((ip_me->ipv6.lo >> 24ULL) & 0xFF);
    px[offset_ip + 21] = (unsigned char)((ip_me->ipv6.lo >> 16ULL) & 0xFF);
    px[offset_ip + 22] = (unsigned char)((ip_me->ipv6.lo >> 8ULL) & 0xFF);
    px[offset_ip + 23] = (unsigned char)((ip_me->ipv6.lo >> 0ULL) & 0xFF);

    px[offset_ip + 24] = (unsigned char)((ip_them->ipv6.hi >> 56ULL) & 0xFF);
    px[offset_ip + 25] = (unsigned char)((ip_them->ipv6.hi >> 48ULL) & 0xFF);
    px[offset_ip + 26] = (unsigned char)((ip_them->ipv6.hi >> 40ULL) & 0xFF);
    px[offset_ip + 27] = (unsigned char)((ip_them->ipv6.hi >> 32ULL) & 0xFF);
    px[offset_ip + 28] = (unsigned char)((ip_them->ipv6.hi >> 24ULL) & 0xFF);
    px[offset_ip + 29] = (unsigned char)((ip_them->ipv6.hi >> 16ULL) & 0xFF);
    px[offset_ip + 30] = (unsigned char)((ip_them->ipv6.hi >> 8ULL) & 0xFF);
    px[offset_ip + 31] = (unsigned char)((ip_them->ipv6.hi >> 0ULL) & 0xFF);

    px[offset_ip + 32] = (unsigned char)((ip_them->ipv6.lo >> 56ULL) & 0xFF);
    px[offset_ip + 33] = (unsigned char)((ip_them->ipv6.lo >> 48ULL) & 0xFF);
    px[offset_ip + 34] = (unsigned char)((ip_them->ipv6.lo >> 40ULL) & 0xFF);
    px[offset_ip + 35] = (unsigned char)((ip_them->ipv6.lo >> 32ULL) & 0xFF);
    px[offset_ip + 36] = (unsigned char)((ip_them->ipv6.lo >> 24ULL) & 0xFF);
    px[offset_ip + 37] = (unsigned char)((ip_them->ipv6.lo >> 16ULL) & 0xFF);
    px[offset_ip + 38] = (unsigned char)((ip_them->ipv6.lo >> 8ULL) & 0xFF);
    px[offset_ip + 39] = (unsigned char)((ip_them->ipv6.lo >> 0ULL) & 0xFF);

    /* now do the same for TCP */
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);

    px[offset_tcp + 8] = (unsigned char)(ackno >> 24);
    px[offset_tcp + 9] = (unsigned char)(ackno >> 16);
    px[offset_tcp + 10] = (unsigned char)(ackno >> 8);
    px[offset_tcp + 11] = (unsigned char)(ackno >> 0);

    px[offset_tcp + 13] = (unsigned char)flags;

    px[offset_tcp + 14] = (unsigned char)(1200 >> 8);
    px[offset_tcp + 15] = (unsigned char)(1200 & 0xFF);

    px[offset_tcp + 16] = (unsigned char)0;
    px[offset_tcp + 17] = (unsigned char)0;

    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 6,
                         (offset_app - offset_tcp) + payload_length,
                         px + offset_tcp);
    px[offset_tcp + 16] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 17] = (unsigned char)(xsum >> 0);

    return offset_app + payload_length;
  }
}

/***************************************************************************
 ***************************************************************************/
static size_t udp_payload_fixup(struct TemplatePacket *tmpl, size_t offset_app,
                                unsigned port, unsigned seqno,
                                unsigned char *px, size_t px_length) {

  const unsigned char *payload = NULL;
  size_t payload_length = 0;
  SET_COOKIE set_cookie = NULL;

  if (payloads_udp_lookup(tmpl->payloads, port, &payload, &payload_length, NULL,
                          NULL, &set_cookie)) {

    if (offset_app + payload_length > px_length) {
      LOG(LEVEL_WARNING, "udp: err generating packet: too much payload\n");
      return offset_app;
    }

    /* Copy over the payloads */
    memcpy(px + offset_app, payload, payload_length);

    /* Change the cookie values */
    if (set_cookie) {
      set_cookie(px + offset_app, payload_length, seqno);
    }
    return offset_app + payload_length;
  }
  return offset_app;
}

void template_set_target_ipv6(struct TemplateSet *tmplset,
                              const ipv6address_t *ip_them, unsigned port_them,
                              const ipv6address_t *ip_me, unsigned port_me,
                              unsigned seqno, unsigned char *px,
                              size_t px_length, size_t *r_length) {

  size_t offset_ip;
  size_t offset_tcp;
  uint64_t xsum;
  struct TemplatePacket *tmpl = NULL;
  uint64_t entropy = tmplset->entropy;
  size_t payload_length;

  *r_length = px_length;

  /* Find out which packet template to use. This is because we can
   * simultaneously scan for both TCP and UDP (and others). We've
   * just overloaded the "port" field to signal which protocol we
   * are using */
  if (port_them >= Templ_TCP && port_them <= Templ_TCP_last) {
    tmpl = &tmplset->pkts[Proto_TCP];
    port_them -= Templ_TCP;
  } else if (port_them >= Templ_UDP && port_them <= Templ_UDP_last) {
    tmpl = &tmplset->pkts[Proto_UDP];
    port_them -= Templ_UDP;
  } else if (port_them >= Templ_SCTP && port_them <= Templ_SCTP_last) {
    tmpl = &tmplset->pkts[Proto_SCTP];
    port_them -= Templ_SCTP;
  } else if (port_them == Templ_ICMP_echo) {
    tmpl = &tmplset->pkts[Proto_ICMP_ping];
    port_them -= Templ_ICMP;
  } else if (port_them == Templ_ICMP_timestamp) {
    tmpl = &tmplset->pkts[Proto_ICMP_timestamp];
    port_them -= Templ_ICMP;
  } else if (port_them >= Templ_ARP && port_them <= Templ_ARP_last) {
    tmpl = &tmplset->pkts[Proto_ARP];
    if (*r_length > tmpl->ipv6.length)
      *r_length = tmpl->ipv6.length;
    memcpy(px, tmpl->ipv6.packet, *r_length);
    return;
  } else if (port_them == Templ_VulnCheck) {
    tmpl = &tmplset->pkts[Proto_VulnCheck];
    port_them -= Templ_VulnCheck;
  } else {
    return;
  }

  /* Create some shorter local variables to work with */
  if (*r_length > tmpl->ipv6.length)
    *r_length = tmpl->ipv6.length;
  memcpy(px, tmpl->ipv6.packet, *r_length);
  if (tmpl->proto == Proto_UDP) {
    *r_length = udp_payload_fixup(tmpl, tmpl->ipv6.offset_app, port_them, seqno,
                                  px, px_length);
  }
  offset_ip = tmpl->ipv6.offset_ip;
  offset_tcp = tmpl->ipv6.offset_tcp;
  // ip_id = ip_them ^ port_them ^ seqno;

  /*

     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Version| Traffic Class |           Flow Label                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Payload Length        |  Next Header  |   Hop Limit   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                         Source Address                        +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                      Destination Address                      +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  /*
   * Fill in the empty fields in the IP header and then re-calculate
   * the checksum.
   */
  payload_length = *r_length - tmpl->ipv6.offset_ip - 40;
  px[offset_ip + 4] = (unsigned char)(payload_length >> 8) & 0xFF;
  px[offset_ip + 5] = (unsigned char)(payload_length >> 0) & 0xFF;
  px[offset_ip + 8] = (unsigned char)((ip_me->hi >> 56ULL) & 0xFF);
  px[offset_ip + 9] = (unsigned char)((ip_me->hi >> 48ULL) & 0xFF);
  px[offset_ip + 10] = (unsigned char)((ip_me->hi >> 40ULL) & 0xFF);
  px[offset_ip + 11] = (unsigned char)((ip_me->hi >> 32ULL) & 0xFF);
  px[offset_ip + 12] = (unsigned char)((ip_me->hi >> 24ULL) & 0xFF);
  px[offset_ip + 13] = (unsigned char)((ip_me->hi >> 16ULL) & 0xFF);
  px[offset_ip + 14] = (unsigned char)((ip_me->hi >> 8ULL) & 0xFF);
  px[offset_ip + 15] = (unsigned char)((ip_me->hi >> 0ULL) & 0xFF);

  px[offset_ip + 16] = (unsigned char)((ip_me->lo >> 56ULL) & 0xFF);
  px[offset_ip + 17] = (unsigned char)((ip_me->lo >> 48ULL) & 0xFF);
  px[offset_ip + 18] = (unsigned char)((ip_me->lo >> 40ULL) & 0xFF);
  px[offset_ip + 19] = (unsigned char)((ip_me->lo >> 32ULL) & 0xFF);
  px[offset_ip + 20] = (unsigned char)((ip_me->lo >> 24ULL) & 0xFF);
  px[offset_ip + 21] = (unsigned char)((ip_me->lo >> 16ULL) & 0xFF);
  px[offset_ip + 22] = (unsigned char)((ip_me->lo >> 8ULL) & 0xFF);
  px[offset_ip + 23] = (unsigned char)((ip_me->lo >> 0ULL) & 0xFF);

  px[offset_ip + 24] = (unsigned char)((ip_them->hi >> 56ULL) & 0xFF);
  px[offset_ip + 25] = (unsigned char)((ip_them->hi >> 48ULL) & 0xFF);
  px[offset_ip + 26] = (unsigned char)((ip_them->hi >> 40ULL) & 0xFF);
  px[offset_ip + 27] = (unsigned char)((ip_them->hi >> 32ULL) & 0xFF);
  px[offset_ip + 28] = (unsigned char)((ip_them->hi >> 24ULL) & 0xFF);
  px[offset_ip + 29] = (unsigned char)((ip_them->hi >> 16ULL) & 0xFF);
  px[offset_ip + 30] = (unsigned char)((ip_them->hi >> 8ULL) & 0xFF);
  px[offset_ip + 31] = (unsigned char)((ip_them->hi >> 0ULL) & 0xFF);

  px[offset_ip + 32] = (unsigned char)((ip_them->lo >> 56ULL) & 0xFF);
  px[offset_ip + 33] = (unsigned char)((ip_them->lo >> 48ULL) & 0xFF);
  px[offset_ip + 34] = (unsigned char)((ip_them->lo >> 40ULL) & 0xFF);
  px[offset_ip + 35] = (unsigned char)((ip_them->lo >> 32ULL) & 0xFF);
  px[offset_ip + 36] = (unsigned char)((ip_them->lo >> 24ULL) & 0xFF);
  px[offset_ip + 37] = (unsigned char)((ip_them->lo >> 16ULL) & 0xFF);
  px[offset_ip + 38] = (unsigned char)((ip_them->lo >> 8ULL) & 0xFF);
  px[offset_ip + 39] = (unsigned char)((ip_them->lo >> 0ULL) & 0xFF);

  /* Now do the checksum for the higher layer protocols */
  switch (tmpl->proto) {
  case Proto_TCP:
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);

    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 6,
                         *r_length - offset_tcp, px + offset_tcp);
    px[offset_tcp + 16] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 17] = (unsigned char)(xsum >> 0);
    break;
  case Proto_UDP:
    /* TODO: IPv6 */
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] =
        (unsigned char)((*r_length - tmpl->ipv6.offset_app + 8) >> 8);
    px[offset_tcp + 5] =
        (unsigned char)((*r_length - tmpl->ipv6.offset_app + 8) & 0xFF);

    px[offset_tcp + 6] = (unsigned char)(0);
    px[offset_tcp + 7] = (unsigned char)(0);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 17,
                         *r_length - offset_tcp, px + offset_tcp);
    px[offset_tcp + 6] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 7] = (unsigned char)(xsum >> 0);
    break;
  case Proto_SCTP:
    /* TODO: IPv6 */
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);

    px[offset_tcp + 16] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 17] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 18] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 19] = (unsigned char)(seqno >> 0);

    xsum = sctp_checksum(px + offset_tcp, *r_length - offset_tcp);
    px[offset_tcp + 8] = (unsigned char)(xsum >> 24);
    px[offset_tcp + 9] = (unsigned char)(xsum >> 16);
    px[offset_tcp + 10] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 11] = (unsigned char)(xsum >> 0);
    break;
  case Proto_ICMP_ping:
  case Proto_ICMP_timestamp:
    /* TODO: IPv6 */
    seqno = (unsigned)syn_cookie_ipv6(ip_them, port_them, ip_me, 0, entropy);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 58,
                         *r_length - offset_tcp, px + offset_tcp);
    px[offset_tcp + 2] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 3] = (unsigned char)(xsum >> 0);
    break;
  case Proto_VulnCheck:
    /* TODO: IPv6 */
    /* tmplset->vulncheck->set_target(tmpl,
                                ip_them, port_them,
                                ip_me, port_me,
                                seqno,
                                px, sizeof_px, r_length);*/
    break;
  case Proto_ARP:
    /* TODO: IPv6 */
    /* don't do any checksumming */
    break;
  case Proto_Oproto:
    /* TODO: IPv6 */
    /* TODO: probably need to add checksums for certain protocols */
    break;
  case Proto_Count:
    break;
  }
}

/***************************************************************************
 * This is the function that formats the transmitted packets for probing
 * machines. It takes a template for the protocol (usually a TCP SYN
 * packet), then sets the destination IP address and port numbers.
 ***************************************************************************/
void template_set_target_ipv4(struct TemplateSet *tmplset,
                              const ipv4address_t *ip_them, unsigned port_them,
                              const ipv4address_t *ip_me, unsigned port_me,
                              unsigned seqno, unsigned char *px,
                              size_t px_length, size_t *r_length) {

  size_t offset_ip;
  size_t offset_tcp;
  uint64_t xsum;
  unsigned ip_id;
  size_t ip_len;
  struct TemplatePacket *tmpl = NULL;
  unsigned xsum2;
  uint64_t entropy = tmplset->entropy;

  *r_length = px_length;

  /* Find out which packet template to use. This is because we can
   * simultaneously scan for both TCP and UDP (and others). We've
   * just overloaded the "port" field to signal which protocol we
   * are using */
  if (port_them >= Templ_TCP && port_them <= Templ_TCP_last) {
    tmpl = &tmplset->pkts[Proto_TCP];
    port_them -= Templ_TCP;
  } else if (port_them >= Templ_UDP && port_them <= Templ_UDP_last) {
    tmpl = &tmplset->pkts[Proto_UDP];
    port_them -= Templ_UDP;
  } else if (port_them >= Templ_SCTP && port_them <= Templ_SCTP_last) {
    tmpl = &tmplset->pkts[Proto_SCTP];
    port_them -= Templ_SCTP;
  } else if (port_them == Templ_ICMP_echo) {
    tmpl = &tmplset->pkts[Proto_ICMP_ping];
    port_them -= Templ_ICMP;
  } else if (port_them == Templ_ICMP_timestamp) {
    tmpl = &tmplset->pkts[Proto_ICMP_timestamp];
    port_them -= Templ_ICMP;
  } else if (port_them >= Templ_ARP && port_them <= Templ_ARP_last) {
    tmpl = &tmplset->pkts[Proto_ARP];
    if (*r_length > tmpl->ipv4.length)
      *r_length = tmpl->ipv4.length;
    memcpy(px, tmpl->ipv4.packet, *r_length);
    px += tmpl->ipv4.offset_ip;
    px[14] = (unsigned char)((*ip_me >> 24) & 0xFF);
    px[15] = (unsigned char)((*ip_me >> 16) & 0xFF);
    px[16] = (unsigned char)((*ip_me >> 8) & 0xFF);
    px[17] = (unsigned char)((*ip_me >> 0) & 0xFF);
    px[24] = (unsigned char)((*ip_them >> 24) & 0xFF);
    px[25] = (unsigned char)((*ip_them >> 16) & 0xFF);
    px[26] = (unsigned char)((*ip_them >> 8) & 0xFF);
    px[27] = (unsigned char)((*ip_them >> 0) & 0xFF);
    return;
  } else if (port_them == Templ_VulnCheck) {
    tmpl = &tmplset->pkts[Proto_VulnCheck];
    port_them -= Templ_VulnCheck;
  } else {
    return;
  }

  /* Create some shorter local variables to work with */
  if (*r_length > tmpl->ipv4.length)
    *r_length = tmpl->ipv4.length;
  memcpy(px, tmpl->ipv4.packet, *r_length);
  if (tmpl->proto == Proto_UDP) {
    *r_length = udp_payload_fixup(tmpl, tmpl->ipv4.offset_app, port_them, seqno,
                                  px, px_length);
  }
  offset_ip = tmpl->ipv4.offset_ip;
  offset_tcp = tmpl->ipv4.offset_tcp;
  ip_id = *ip_them ^ port_them ^ seqno;
  ip_len = *r_length - tmpl->ipv4.offset_ip;

  /*

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version|  IHL  |Type of Service|          Total Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Identification        |Flags|      Fragment Offset    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Time to Live |    Protocol   |         Header Checksum       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Source Address                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Destination Address                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

  /* Fill in the empty fields in the IP header and then re-calculate
   * the checksum. */
  px[offset_ip + 2] = (unsigned char)(ip_len >> 8);
  px[offset_ip + 3] = (unsigned char)(ip_len & 0xFF);
  px[offset_ip + 4] = (unsigned char)(ip_id >> 8);
  px[offset_ip + 5] = (unsigned char)(ip_id & 0xFF);
  px[offset_ip + 12] = (unsigned char)((*ip_me >> 24) & 0xFF);
  px[offset_ip + 13] = (unsigned char)((*ip_me >> 16) & 0xFF);
  px[offset_ip + 14] = (unsigned char)((*ip_me >> 8) & 0xFF);
  px[offset_ip + 15] = (unsigned char)((*ip_me >> 0) & 0xFF);
  px[offset_ip + 16] = (unsigned char)((*ip_them >> 24) & 0xFF);
  px[offset_ip + 17] = (unsigned char)((*ip_them >> 16) & 0xFF);
  px[offset_ip + 18] = (unsigned char)((*ip_them >> 8) & 0xFF);
  px[offset_ip + 19] = (unsigned char)((*ip_them >> 0) & 0xFF);

  px[offset_ip + 10] = (unsigned char)(0);
  px[offset_ip + 11] = (unsigned char)(0);

  xsum2 = (unsigned)~ip_header_checksum(px, offset_ip, px_length);

  px[offset_ip + 10] = (unsigned char)(xsum2 >> 8);
  px[offset_ip + 11] = (unsigned char)(xsum2 & 0xFF);

  /* Now do the checksum for the higher layer protocols */
  xsum = 0;
  switch (tmpl->proto) {
  case Proto_TCP:
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);

    xsum += (uint64_t)tmpl->ipv4.checksum_tcp + (uint64_t)*ip_me +
            (uint64_t)*ip_them + (uint64_t)port_me + (uint64_t)port_them +
            (uint64_t)seqno;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    px[offset_tcp + 16] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 17] = (unsigned char)(xsum >> 0);
    break;
  case Proto_UDP:
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp + 4] =
        (unsigned char)((*r_length - tmpl->ipv4.offset_app + 8) >> 8);
    px[offset_tcp + 5] =
        (unsigned char)((*r_length - tmpl->ipv4.offset_app + 8) & 0xFF);

    px[offset_tcp + 6] = (unsigned char)(0);
    px[offset_tcp + 7] = (unsigned char)(0);
    xsum = udp_checksum2(px, offset_ip, offset_tcp, *r_length - offset_tcp);
    xsum = ~xsum;
    px[offset_tcp + 6] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 7] = (unsigned char)(xsum >> 0);
    break;
  case Proto_SCTP:
    px[offset_tcp + 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp + 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp + 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp + 3] = (unsigned char)(port_them & 0xFF);

    px[offset_tcp + 16] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 17] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 18] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 19] = (unsigned char)(seqno >> 0);

    xsum = sctp_checksum(px + offset_tcp, *r_length - offset_tcp);
    px[offset_tcp + 8] = (unsigned char)(xsum >> 24);
    px[offset_tcp + 9] = (unsigned char)(xsum >> 16);
    px[offset_tcp + 10] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 11] = (unsigned char)(xsum >> 0);
    break;
  case Proto_ICMP_ping:
  case Proto_ICMP_timestamp:
    seqno = (unsigned)syn_cookie_ipv4(ip_them, port_them, ip_me, 0, entropy);
    px[offset_tcp + 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp + 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp + 6] = (unsigned char)(seqno >> 8);
    px[offset_tcp + 7] = (unsigned char)(seqno >> 0);
    xsum = (uint64_t)tmpl->ipv4.checksum_tcp + (uint64_t)seqno;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;
    px[offset_tcp + 2] = (unsigned char)(xsum >> 8);
    px[offset_tcp + 3] = (unsigned char)(xsum >> 0);
    break;
  case Proto_VulnCheck:
    tmplset->vulncheck->set_target(tmpl, ip_them, port_them, ip_me, port_me,
                                   seqno, px, px_length, r_length);
    break;
  case Proto_ARP:
    /* don't do any checksumming */
    break;
  case Proto_Oproto:
    /* TODO: probably need to add checksums for certain protocols */
    break;
  case Proto_Count:
    break;
  }
}

#if defined(WIN32) || defined(_WIN32)
#define AF_INET6 23
#else
#include <sys/socket.h>
#endif

/***************************************************************************
 * Creates an IPv6 packet from an IPv4 template, by simply replacing
 * the IPv4 header with the IPv6 header.
 ***************************************************************************/
static void _template_init_ipv6(struct TemplatePacket *tmpl,
                                const macaddress_t *router_mac_ipv6,
                                unsigned data_link_type) {

  struct PreprocessedInfo parsed;
  unsigned x;
  size_t payload_length;
  size_t offset_ip;
  size_t offset_tcp;
  size_t offset_tcp6;
  unsigned char *buf;
  size_t size_buf;

  /* Zero out everything and start from scratch */
  if (tmpl->ipv6.packet) {
    free(tmpl->ipv6.packet);
    memset(&tmpl->ipv6, 0, sizeof(tmpl->ipv6));
  }

  /* Parse the existing IPv4 packet */
  x = preprocess_frame(tmpl->ipv4.packet, tmpl->ipv4.length, data_link_type,
                       &parsed);
  if (!x || parsed.found == FOUND_NOTHING) {
    LOG(LEVEL_ERROR, "ERROR: bad packet template\n");
    exit(1);
  }

  /* The "payload" in this case is everything past the IP header,
   * so TCP or UDP headers are inside the IP payload */
  payload_length = tmpl->ipv4.length - tmpl->ipv4.offset_tcp;
  offset_ip = tmpl->ipv4.offset_ip;
  offset_tcp = tmpl->ipv4.offset_tcp;

  /* Create a copy of the IPv4 packet */
  size_buf = tmpl->ipv4.length + 40;
  buf = MALLOC(size_buf);
  memcpy(buf, tmpl->ipv4.packet, tmpl->ipv4.length);
  tmpl->ipv6.packet = buf;

  /* destination = end of IPv6 header
   * source = end of IPv4 header
   * contents = everything after IPv4/IPv6 header */
  offset_tcp6 = offset_ip + 40;
  memmove(buf + offset_tcp6, buf + offset_tcp, payload_length);

  /* fill the IPv6 header with zeroes */
  memset(buf + offset_ip, 0, 40);
  tmpl->ipv6.length = offset_ip + 40 + payload_length;

  switch (data_link_type) {
  case PCAP_DLT_NULL: /* Null VPN tunnel */
    /* FIXME: insert platform dependent value here */
    *(int *)buf = AF_INET6;
    break;
  case PCAP_DLT_RAW: /* Raw (nothing before IP header) */
    break;
  case PCAP_DLT_ETHERNET: /* Ethernet */
    /* Reset the destination MAC address to be the IPv6 router
     * instead of the IPv4 router, which sometimes are different */
    memcpy(buf + 0, router_mac_ipv6->addr, 6);

    /* Reset the Ethertype field to 0x86dd (meaning IPv6) */
    buf[12] = 0x86;
    buf[13] = 0xdd;
    break;
  }

  /* IP.version = 6 */
  buf[offset_ip + 0] = 0x60;

  /* Set payload length field. In IPv4, this field included the header,
   * but in IPv6, it's everything after the header. In other words,
   * the size of an IPv6 packet is 40+payload_length, whereas in IPv4
   * it was total_length. */
  buf[offset_ip + 4] = (unsigned char)(payload_length >> 8);
  buf[offset_ip + 5] = (unsigned char)(payload_length >> 0);

  /* Set the "next header" field.
   * TODO: need to fix ICMP */
  buf[offset_ip + 6] = (unsigned char)parsed.ip_protocol;
  if (parsed.ip_protocol == 1) {
    buf[offset_ip + 6] = 58; /* ICMPv6 */
    if (payload_length > 0 && buf[offset_tcp6 + 0] == 8) {
      /* PING -> PINGv6 */
      buf[offset_tcp6 + 0] = 128;
    }
  }

  /* Hop limit starts out as 255 */
  buf[offset_ip + 7] = 0xFF;

  /* Parse our newly construct IPv6 packet */
  x = preprocess_frame(buf, tmpl->ipv6.length, data_link_type, &parsed);
  if (!x || parsed.found == FOUND_NOTHING) {
    LOG(LEVEL_ERROR, "[-] FAILED: bad packet template\n");
    exit(1);
  }
  tmpl->ipv6.offset_ip = parsed.ip_offset;
  tmpl->ipv6.offset_tcp = parsed.transport_offset;
  tmpl->ipv6.offset_app = parsed.app_offset;
}

/***************************************************************************
 * Here we take a packet template, parse it, then make it easier to work
 * with.
 ***************************************************************************/
static void _template_init(struct TemplatePacket *tmpl,
                           const macaddress_t *source_mac,
                           const macaddress_t *router_mac_ipv4,
                           const macaddress_t *router_mac_ipv6,
                           const void *packet_bytes, size_t packet_size,
                           unsigned data_link_type) {

  unsigned char *px;
  struct PreprocessedInfo parsed;
  unsigned x;

  /* Create the new template structure:
   * - zero it out
   * - make copy of the old packet to serve as new template */
  memset(tmpl, 0, sizeof(*tmpl));
  tmpl->ipv4.length = packet_size;
  tmpl->ipv4.packet = MALLOC(tmpl->ipv4.length);
  memcpy(tmpl->ipv4.packet, packet_bytes, packet_size);
  px = tmpl->ipv4.packet;

  /* Parse the existing packet template. We support TCP, UDP, ICMP,
   * and ARP packets. */
  x = preprocess_frame(px, tmpl->ipv4.length, 1 /*enet*/, &parsed);
  if (!x || parsed.found == FOUND_NOTHING) {
    LOG(LEVEL_ERROR, "ERROR: bad packet template\n");
    exit(1);
  }
  tmpl->ipv4.offset_ip = parsed.ip_offset;
  tmpl->ipv4.offset_tcp = parsed.transport_offset;
  tmpl->ipv4.offset_app = parsed.app_offset;
  if (parsed.found == FOUND_ARP) {
    tmpl->ipv4.length = parsed.ip_offset + 28;
  } else {
    tmpl->ipv4.length = parsed.ip_offset + parsed.ip_length;
  }

  /* Overwrite the MAC and IP addresses */
  memcpy(px + 0, router_mac_ipv4->addr, 6);
  memcpy(px + 6, source_mac->addr, 6);
  memset(parsed._ip_src, 0, 4);
  memset(parsed._ip_dst, 0, 4);

  /* ARP
   *
   * If this is an ARP template (for doing arpscans), then just set our
   * configured source IP and MAC addresses. */
  if (parsed.found == FOUND_ARP) {
    memcpy((char *)parsed._ip_src - 6, source_mac->addr, 6);
    tmpl->proto = Proto_ARP;
    return;
  }

  /* IPv4
   *
   * Calculate the partial checksum. We zero out the fields that will be
   * added later the packet, then calculate the checksum as if they were
   * zero. This makes recalculation of the checksum easier when we transmit */
  memset(px + tmpl->ipv4.offset_ip + 4, 0, 2);  /* IP ID field */
  memset(px + tmpl->ipv4.offset_ip + 10, 0, 2); /* checksum */
  memset(px + tmpl->ipv4.offset_ip + 12, 0, 8); /* addresses */
  tmpl->ipv4.checksum_ip = ip_header_checksum(
      tmpl->ipv4.packet, tmpl->ipv4.offset_ip, tmpl->ipv4.length);

  /* Higher layer protocols: zero out dest/checksum fields, then calculate
   * a partial checksum */
  switch (parsed.ip_protocol) {
  case 1: /* ICMP */
    tmpl->ipv4.offset_app = tmpl->ipv4.length;
    tmpl->ipv4.checksum_tcp = icmp_ipv4_checksum(tmpl);
    switch (px[tmpl->ipv4.offset_tcp]) {
    case 8:
      tmpl->proto = Proto_ICMP_ping;
      break;
    case 13:
      tmpl->proto = Proto_ICMP_timestamp;
      break;
    }
    break;
  case 6: /* TCP */
    /* zero out fields that'll be overwritten */
    memset(px + tmpl->ipv4.offset_tcp + 0, 0,
           8); /* destination port and seqno */
    memset(px + tmpl->ipv4.offset_tcp + 16, 0, 2); /* checksum */
    tmpl->ipv4.checksum_tcp = tcp_ipv4_checksum(tmpl);
    tmpl->proto = Proto_TCP;
    break;
  case 17:                                        /* UDP */
    memset(px + tmpl->ipv4.offset_tcp + 6, 0, 2); /* checksum */
    tmpl->ipv4.checksum_tcp = udp_ipv4_checksum(tmpl);
    tmpl->proto = Proto_UDP;
    break;
  case 132: /* SCTP */
    tmpl->ipv4.checksum_tcp =
        sctp_checksum(tmpl->ipv4.packet + tmpl->ipv4.offset_tcp,
                      tmpl->ipv4.length - tmpl->ipv4.offset_tcp);
    tmpl->proto = Proto_SCTP;
    break;
  }

  /*
   * DATALINK KLUDGE
   *
   * Adjust the data link header in case of Raw IP packets. This isn't
   * the correct way to do this, but I'm too lazy to refactor code
   * for the right way, so we'll do it this way now.
   */
  if (data_link_type == PCAP_DLT_NULL /* Null VPN tunnel */) {
    int linkproto = 2; /* AF_INET */
    size_t ipv4_old_length = tmpl->ipv4.length;
    tmpl->ipv4.length -= tmpl->ipv4.offset_ip - sizeof(int);
    tmpl->ipv4.offset_tcp -= tmpl->ipv4.offset_ip - sizeof(int);
    tmpl->ipv4.offset_app -= tmpl->ipv4.offset_ip - sizeof(int);
    memmove(tmpl->ipv4.packet + sizeof(int),
            tmpl->ipv4.packet + tmpl->ipv4.offset_ip,
            ipv4_old_length - tmpl->ipv4.offset_ip);
    tmpl->ipv4.offset_ip = 4;
    memcpy(tmpl->ipv4.packet, &linkproto, sizeof(int));
  } else if (data_link_type == PCAP_DLT_RAW /* Raw IP */) {
    size_t ipv4_old_length = tmpl->ipv4.length;
    tmpl->ipv4.length -= tmpl->ipv4.offset_ip;
    tmpl->ipv4.offset_tcp -= tmpl->ipv4.offset_ip;
    tmpl->ipv4.offset_app -= tmpl->ipv4.offset_ip;
    memmove(tmpl->ipv4.packet, tmpl->ipv4.packet + tmpl->ipv4.offset_ip,
            ipv4_old_length - tmpl->ipv4.offset_ip);
    tmpl->ipv4.offset_ip = 0;
  } else if (data_link_type == PCAP_DLT_ETHERNET) {
    /* the default, do nothing */
  } else {
    LOG(LEVEL_ERROR,
        "[-] FAILED: bad packet template, unknown data link type\n");
    LOG(LEVEL_ERROR, "    [hint] masscan doesn't know how to format packets "
                     "for this interface\n");
    exit(1);
  }

  /* Now create an IPv6 template based upon the IPv4 template */
  _template_init_ipv6(tmpl, router_mac_ipv6, data_link_type);
}

static void _template_cleanup(struct TemplatePacket *tmpl) {
  if (tmpl->ipv4.packet != NULL) {
    free(tmpl->ipv4.packet);
  }
  if (tmpl->ipv6.packet != NULL) {
    free(tmpl->ipv6.packet);
  }
  memset(tmpl, 0, sizeof(*tmpl));
}

/***************************************************************************
 ***************************************************************************/
void template_packet_init(struct TemplateSet *templset,
                          const macaddress_t *source_mac,
                          const macaddress_t *router_mac_ipv4,
                          const macaddress_t *router_mac_ipv6,
                          struct PayloadsUDP *udp_payloads,
                          struct PayloadsUDP *oproto_payloads, int data_link,
                          uint64_t entropy) {

  templset->count = 0;
  templset->entropy = entropy;

  /* [SCTP] */
  _template_init(&templset->pkts[Proto_SCTP], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_sctp_template,
                 sizeof(default_sctp_template) - 1, data_link);
  templset->count++;

  /* [TCP] */
  _template_init(&templset->pkts[Proto_TCP], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_tcp_template,
                 sizeof(default_tcp_template) - 1, data_link);
  templset->count++;

  /* [UDP] */
  _template_init(&templset->pkts[Proto_UDP], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_udp_template,
                 sizeof(default_udp_template) - 1, data_link);
  templset->pkts[Proto_UDP].payloads = udp_payloads;
  templset->count++;

  /* [UDP oproto] */
  _template_init(&templset->pkts[Proto_Oproto], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_udp_template,
                 sizeof(default_udp_template) - 1, data_link);
  templset->pkts[Proto_Oproto].payloads = oproto_payloads;
  templset->count++;

  /* [ICMP ping] */
  _template_init(&templset->pkts[Proto_ICMP_ping], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_icmp_ping_template,
                 sizeof(default_icmp_ping_template) - 1, data_link);
  templset->count++;

  /* [ICMP timestamp] */
  _template_init(&templset->pkts[Proto_ICMP_timestamp], source_mac,
                 router_mac_ipv4, router_mac_ipv6,
                 default_icmp_timestamp_template,
                 sizeof(default_icmp_timestamp_template) - 1, data_link);
  templset->count++;

  /* [ARP] */
  _template_init(&templset->pkts[Proto_ARP], source_mac, router_mac_ipv4,
                 router_mac_ipv6, default_arp_template,
                 sizeof(default_arp_template) - 1, data_link);
  templset->count++;

  /* [VulnCheck] */
  if (templset->vulncheck) {
    _template_init(&templset->pkts[Proto_VulnCheck], source_mac,
                   router_mac_ipv4, router_mac_ipv6,
                   templset->vulncheck->packet,
                   templset->vulncheck->packet_length, data_link);
    templset->count++;
  }
}

void template_packet_cleanup(struct TemplateSet *templset) {
  if (templset->vulncheck) {
    _template_cleanup(&templset->pkts[Proto_VulnCheck]);
    templset->count--;
  }

  _template_cleanup(&templset->pkts[Proto_ARP]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_ICMP_timestamp]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_ICMP_ping]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_Oproto]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_UDP]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_TCP]);
  templset->count--;

  _template_cleanup(&templset->pkts[Proto_SCTP]);
  templset->count--;

  assert(templset->count == 0);
  templset->count = 0;
  templset->entropy = 0;
}

/***************************************************************************
 * Overwrites the TTL of the packet
 ***************************************************************************/
void template_set_ttl(struct TemplateSet *tmplset, unsigned ttl) {
  size_t i;

  for (i = 0; i < tmplset->count; i++) {
    struct TemplatePacket *tmpl = &tmplset->pkts[i];
    unsigned char *px = tmpl->ipv4.packet;
    size_t offset = tmpl->ipv4.offset_ip;

    px[offset + 8] = (unsigned char)(ttl);
    tmpl->ipv4.checksum_ip = ip_header_checksum(
        tmpl->ipv4.packet, tmpl->ipv4.offset_ip, tmpl->ipv4.length);
  }
}

void template_set_vlan(struct TemplateSet *tmplset, unsigned vlan) {

  size_t i;

  for (i = 0; i < tmplset->count; i++) {
    struct TemplatePacket *tmpl = &tmplset->pkts[i];
    unsigned char *px;
    size_t size_px;

    if (tmpl->ipv4.length < 14)
      continue;
    size_px = tmpl->ipv4.length + 4;
    px = MALLOC(size_px);
    memcpy(px, tmpl->ipv4.packet, 12);
    memcpy(px + 16, tmpl->ipv4.packet + 12, tmpl->ipv4.length - 12);

    px[12] = 0x81;
    px[13] = 0x00;
    px[14] = (unsigned char)(vlan >> 8);
    px[15] = (unsigned char)(vlan >> 0);

    tmpl->ipv4.packet = px;
    tmpl->ipv4.length = size_px;

    tmpl->ipv4.offset_ip += 4;
    tmpl->ipv4.offset_tcp += 4;
    tmpl->ipv4.offset_app += 4;
  }
}

/***************************************************************************
 ***************************************************************************/
int template_selftest(void) {
  struct TemplateSet tmplset[1];
  macaddress_t mac1, mac2, mac3;
  int failures = 0;

  memset(tmplset, 0, sizeof(tmplset[0]));
  template_packet_init(tmplset,
                       macaddress_from_bytes(&mac1, "\x00\x11\x22\x33\x44\x55"),
                       macaddress_from_bytes(&mac2, "\x66\x55\x44\x33\x22\x11"),
                       macaddress_from_bytes(&mac3, "\x66\x55\x44\x33\x22\x11"),
                       0, /* UDP payloads = empty */
                       0, /* Oproto payloads = empty */
                       1, /* Ethernet */
                       0  /* no entropy */
  );
  failures += tmplset->pkts[Proto_TCP].proto != Proto_TCP;
  failures += tmplset->pkts[Proto_UDP].proto != Proto_UDP;
  // failures += tmplset->pkts[Proto_SCTP].proto != Proto_SCTP;
  failures += tmplset->pkts[Proto_ICMP_ping].proto != Proto_ICMP_ping;
  // failures += tmplset->pkts[Proto_ICMP_timestamp].proto !=
  // Proto_ICMP_timestamp; failures += tmplset->pkts[Proto_ARP].proto  !=
  // Proto_ARP;

  if (failures) {
    LOG(LEVEL_ERROR, "template: failed\n");
  }

  template_packet_cleanup(tmplset);
  return failures;
}
