#ifndef PROTO_SNMP_H
#define PROTO_SNMP_H
#include <stdint.h>
#include <time.h>

#include "proto-banner1.h"

struct Output;
struct PreprocessedInfo;

/* Need to call this on startup to compile the internal MIB. */
void snmp_init(void);

/* Does a regression test.
 * @return
 *     0 if success, 1 if failure */
int snmp_selftest(void);

unsigned snmp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

unsigned handle_snmp(struct Banner1 *banner1, struct Output *out,
                     time_t timestamp, const unsigned char *px, size_t length,
                     struct PreprocessedInfo *parsed, uint64_t entropy);
#endif
