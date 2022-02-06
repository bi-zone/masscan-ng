#ifndef PROTO_ICMP_H
#define PROTO_ICMP_H
#include <stdint.h>
#include <time.h>
struct PreprocessedInfo;
struct Output;

void handle_icmp(struct Output *out, time_t timestamp, const unsigned char *px,
                 size_t length, struct PreprocessedInfo *parsed,
                 uint64_t entropy);

#endif
