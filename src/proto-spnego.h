#ifndef PROTO_SPNEGO_H
#define PROTO_SPNEGO_H

#include "proto-asn1.h"
#include "proto-ntlmssp.h"

struct SpnegoDecode {
  struct ASN1Decode asn1;
  struct NtlmsspDecode ntlmssp;
  size_t count_mech_types;
  unsigned is_printed_mech_types : 1;
};

void spnego_decode_init(struct SpnegoDecode *x, size_t length);

void spnego_decode(struct SpnegoDecode *x, const unsigned char *px,
                   size_t length, struct BannerOutput *banout);

void spnego_init(void);

int spnego_selftest(void);

#endif
