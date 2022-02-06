#ifndef PROTO_NTP_H
#define PROTO_NTP_H
#include <stdint.h>
#include <time.h>

#include "proto-banner1.h"

struct Output;
struct PreprocessedInfo;

/* Does a regression test.
 * @return
 *     0 if success, 1 if failure */
int ntp_selftest(void);

/* Sets a cookie on the packet, if possible. */
unsigned ntp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

/* Parse NTP responses looking for any "banner" information */
unsigned ntp_handle_response(struct Banner1 *banner1, struct Output *out,
                             time_t timestamp, const unsigned char *px,
                             size_t length, struct PreprocessedInfo *parsed,
                             uint64_t entropy);

#endif
