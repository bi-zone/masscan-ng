#ifndef PROTO_NETBIOS_H
#define PROTO_NETBIOS_H
#include <stdint.h>
#include <time.h>

#include "proto-banner1.h"

struct PreprocessedInfo;
struct Output;

unsigned handle_nbtstat(struct Banner1 *banner1, struct Output *out,
                        time_t timestamp, const unsigned char *px,
                        size_t length, struct PreprocessedInfo *parsed,
                        uint64_t entropy);

#endif
