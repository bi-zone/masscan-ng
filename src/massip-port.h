#ifndef MASSIP_PORT_H
#define MASSIP_PORT_H

#include "util-cross.h"

#define COUNT_ARP_TYPES 1
/*
 * Ports are 16-bit numbers ([0..65535], but different
 * transports (TCP, UDP, SCTP) are distinct port ranges. Thus, we
 * instead of three 64k ranges we could instead treat this internally
 * as a 192k port range. We can expand this range to include other
 * things we scan for, such as ICMP pings or ARP requests.
 */
enum {
  Templ_TCP = 0,
  Templ_TCP_last = COUNT_TCP_PORTS - 1,
  Templ_UDP = COUNT_TCP_PORTS,
  Templ_UDP_last = COUNT_TCP_PORTS + COUNT_UDP_PORTS - 1,
  Templ_SCTP = COUNT_TCP_PORTS + COUNT_UDP_PORTS,
  Templ_SCTP_last = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS - 1,
  Templ_ICMP = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS,
  Templ_ICMP_echo = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS,
  Templ_ICMP_timestamp =
      COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS + 1,
  Templ_ICMP_last = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS +
                    COUNT_ICMP_TYPES - 1,
  Templ_ARP =
      COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS + COUNT_ICMP_TYPES,
  Templ_ARP_last = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS +
                   COUNT_ICMP_TYPES + COUNT_ARP_TYPES - 1,
  Templ_Oproto = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS +
                 COUNT_ICMP_TYPES + COUNT_ARP_TYPES,
  Templ_Oproto_last = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS +
                      COUNT_ICMP_TYPES + COUNT_ARP_TYPES + COUNT_OPROTO_PORTS -
                      1,
  Templ_VulnCheck = COUNT_TCP_PORTS + COUNT_UDP_PORTS + COUNT_SCTP_PORTS +
                    COUNT_ICMP_TYPES + COUNT_ARP_TYPES + COUNT_OPROTO_PORTS,
};

#endif
