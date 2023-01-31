#ifndef PROTO_ZEROACCESS_H
#define PROTO_ZEROACCESS_H
#include <stdint.h>
#include <time.h>

#include "proto-banner1.h"

struct PreprocessedInfo;
struct Output;

unsigned handle_zeroaccess(struct Banner1 *banner1, struct Output *out,
                           time_t timestamp, const unsigned char *px,
                           size_t length, struct PreprocessedInfo *parsed,
                           uint64_t entropy);

extern char zeroaccess_getL[];
#define zeroaccess_getL_length 16

/* Regression test this module.
 * @return
 *      0 on success, a positive integer otherwise. */
int zeroaccess_selftest(void);

#endif
