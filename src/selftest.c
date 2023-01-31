#include "crypto-base64.h" /* base64 encode/decode */
#include "main-dedup.h"
#include "masscan.h"
#include "massip-parse.h"
#include "massip-rangesv4.h"
#include "massip-rangesv6.h"
#include "misc-rstfilter.h"
#include "output.h"        /* for outputting results */
#include "pixie-timer.h"   /* portable time functions */
#include "proto-arp.h"     /* for responding to ARP requests */
#include "proto-banner1.h" /* for snatching banners from systems */
#include "proto-coap.h"    /* CoAP selftest */
#include "proto-icmp.h"    /* handle ICMP responses */
#include "proto-interactive.h"
#include "proto-ntp.h"        /* parse NTP responses */
#include "proto-oproto.h"     /* Other protocols on top of IP */
#include "proto-preprocess.h" /* quick parse of packets */
#include "proto-sctp.h"
#include "proto-snmp.h" /* parse SNMP responses */
#include "proto-statout.h"
#include "proto-tcp.h" /* for TCP/IP connection table */
#include "proto-udp.h" /* handle UDP responses */
#include "proto-zeroaccess.h"
#include "rand-blackrock.h" /* the BlackRock shuffling func */
#include "rand-lcg.h"       /* the LCG randomization func */
#include "rawsock.h"        /* API on top of Linux, Windows, Mac OS X*/
#include "read-service-probes.h"
#include "siphash24.h"
#include "smack.h"          /* Aho-corasick state-machine pattern-matcher */
#include "templ-payloads.h" /* UDP packet payloads */
#include "transmiter.h"
#include "util-checksum.h"
#include "util-openssl.h"

void benchmark(const struct Masscan *masscan) {
  blackrock_benchmark(masscan->blackrock_rounds);
  blackrock2_benchmark(masscan->blackrock_rounds);
  smack_benchmark();
}

int selftest(const struct Masscan *masscan) {

  int x = 0;

  x += dedup_selftest();
  x += checksum_selftest();
  x += ipv6address_selftest();
  x += transmit_selftest();
  x += proto_coap_selftest();
  x += smack_selftest();
  x += sctp_selftest();
  x += base64_selftest();
  x += banner1_selftest();
  if (masscan->banner1_test_name) {
    x += banner1_test(masscan->banner1_test_name);
  }
  x += output_selftest();
  x += siphash24_selftest();
  x += ntp_selftest();
  x += snmp_selftest();
  x += spnego_selftest();
  x += payloads_udp_selftest();
  x += blackrock_selftest();
  x += rawsock_selftest();
  x += lcg_selftest();
  x += template_selftest();
  x += ranges_selftest();
  x += ranges6_selftest();
  x += massip_parse_selftest();
  x += massip_selftest();
  x += pixie_time_selftest();
  x += rte_ring_selftest();
  x += mainconf_selftest();
  x += zeroaccess_selftest();
  x += nmapserviceprobes_selftest();
  x += rstfilter_selftest();

  x += interactive_data_selftest();
  x += util_openssl_selftest();

  return x;
}