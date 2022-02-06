#include "proto-udp.h"
#include "logger.h"
#include "masscan-status.h"
#include "output.h"
#include "proto-coap.h"
#include "proto-dns.h"
#include "proto-memcached.h"
#include "proto-netbios.h"
#include "proto-ntp.h"
#include "proto-preprocess.h"
#include "proto-snmp.h"
#include "proto-zeroaccess.h"
#include "syn-cookie.h"
#include "util-cross.h"
#include "util-malloc.h"

struct UDP_ConnectionTable {
  struct Banner1 *banner1;
};

/***************************************************************************
 * Called at startup, by a receive thread, to create a UDP connection
 * table.
 ***************************************************************************/
struct UDP_ConnectionTable *udpcon_create_table() {
  struct UDP_ConnectionTable *udpcon;
  udpcon = CALLOC(1, sizeof(*udpcon));
  udpcon->banner1 = banner1_create();
  return udpcon;
}

/***************************************************************************
 * Called at shutdown to free up all the memory used by the UDP
 * connection table.
 ***************************************************************************/
void udpcon_destroy_table(struct UDP_ConnectionTable *udpcon) {
  if (udpcon == NULL)
    return;
  banner1_destroy(udpcon->banner1);
  udpcon->banner1 = NULL;
  free(udpcon);
}

void udpcon_init_banner1(struct UDP_ConnectionTable *udpcon) {
  banner1_init(udpcon->banner1);
}

/****************************************************************************
 * When the "--banner" command-line option is selected, this will
 * will take up to 64 bytes of a response and display it. Other UDP
 * protocol parsers may also default to this function when they detect
 * a response is not the protocol they expect. For example, if a response
 * to port 161 obviously isn't ASN.1 formatted, the SNMP parser will
 * call this function instead. In such cases, the protocool identifier will
 * be [unknown] rather than [snmp].
 ****************************************************************************/
unsigned default_udp_parse(struct Banner1 *banner1, struct Output *out,
                           time_t timestamp, const unsigned char *px,
                           size_t length, struct PreprocessedInfo *parsed,
                           uint64_t entropy) {

  ipaddress ip_them = parsed->src_ip;
  unsigned port_them = parsed->port_src;
  UNUSEDPARM(entropy);
  UNUSEDPARM(banner1);

  if (length > 64) {
    length = 64;
  }

  output_report_banner(out, timestamp, &ip_them, 17 /*udp*/, port_them,
                       PROTO_NONE, parsed->ip_ttl, px, length);

  return 0;
}

/****************************************************************************
 ****************************************************************************/
void handle_udp(struct UDP_ConnectionTable *udpcon, struct Output *out,
                time_t timestamp, const unsigned char *px, size_t length,
                struct PreprocessedInfo *parsed, uint64_t entropy) {

  ipaddress ip_them = parsed->src_ip;
  unsigned port_them = parsed->port_src;
  struct Banner1 *banner1 = NULL;
  unsigned status = 0;

  if (udpcon != NULL) {
    banner1 = udpcon->banner1;
  }

  switch (port_them) {
  case 53: /* DNS - Domain Name System (amplifier) */
    status = handle_dns(banner1, out, timestamp, px, length, parsed, entropy);
    break;
  case 123: /* NTP - Network Time Protocol (amplifier) */
    status = ntp_handle_response(banner1, out, timestamp, px, length, parsed,
                                 entropy);
    break;
  case 137: /* NetBIOS (amplifier) */
    status =
        handle_nbtstat(banner1, out, timestamp, px, length, parsed, entropy);
    break;
  case 161: /* SNMP - Simple Network Managment Protocol (amplifier) */
    status = handle_snmp(banner1, out, timestamp, px, length, parsed, entropy);
    break;
  case 5683:
    status =
        coap_handle_response(banner1, out, timestamp, px + parsed->app_offset,
                             parsed->app_length, parsed, entropy);
    break;
  case 11211: /* memcached (amplifier) */
    px += parsed->app_offset;
    length = parsed->app_length;
    status = memcached_udp_parse(banner1, out, timestamp, px, length, parsed,
                                 entropy);
    break;
  case 16464:
  case 16465:
  case 16470:
  case 16471:
    status =
        handle_zeroaccess(banner1, out, timestamp, px, length, parsed, entropy);
    break;
  default:
    px += parsed->app_offset;
    length = parsed->app_length;
    status =
        default_udp_parse(banner1, out, timestamp, px, length, parsed, entropy);
    break;
  }

  if (status == 0) {
    output_report_status(out, timestamp, PortStatus_Open, &ip_them,
                         17 /* ip proto = udp */, port_them, 0, 0,
                         parsed->mac_src);
  }
}
