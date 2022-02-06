#ifndef PROTO_UDP_H
#define PROTO_UDP_H
#include <stdint.h>
#include <time.h>

#include "proto-banner1.h"

struct PreprocessedInfo;
struct Output;
struct UDP_ConnectionTable;

struct UDP_ConnectionTable *udpcon_create_table();
void udpcon_destroy_table(struct UDP_ConnectionTable *udpcon);
void udpcon_init_banner1(struct UDP_ConnectionTable *udpcon);

/* Parse an incoming UDP response. We parse the basics, then hand it off
 * to a protocol parser (SNMP, NetBIOS, NTP, etc.)
 * @param entropy
 *      The random seed, used in calculating syn-cookies. */
void handle_udp(struct UDP_ConnectionTable *udpcon, struct Output *out,
                time_t timestamp, const unsigned char *px, size_t length,
                struct PreprocessedInfo *parsed, uint64_t entropy);

/* Default banner for UDP, consisting of the first 64 bytes, when it isn't
 * detected as the appropriate protocol */
unsigned default_udp_parse(struct Banner1 *banner1, struct Output *out,
                           time_t timestamp, const unsigned char *px,
                           size_t length, struct PreprocessedInfo *parsed,
                           uint64_t entropy);

#endif
