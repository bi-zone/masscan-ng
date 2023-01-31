#ifndef PROTO_ASN1_H
#define PROTO_ASN1_H

#include "util-cross.h"
#include <stdint.h>

#define STATE_ASN1_ERROR 0xFFFFFFFF

struct ASN1Decode {
  /** This is the master 'state' variable in the massive switch statement */
  unsigned state;

  /** ASN.1 nests fields within fields. Therefore, as we parse down into
   * the structure, we push the parent length/state info on the stack,
   * and then when we exit a field, we pop it back off the stack.
   * NOTE: since space is at a premium, we have separate arrays
   * for the length/state, instead of an array of objects containing
   * both. */
  struct {
    unsigned states[9];
    size_t remainings[9];
    size_t depth;
  } stack;

  unsigned child_state;
  unsigned brother_state;

  /** We catch some DER non-canonical encoding errors, but not all. Someday
   * we'll improve the parser to catch all of them */
  unsigned is_der_failure : 1;

  /** This union contains the intermediate/partial values as we are decoding
   * them. Since a packet may end with a field only partially decoded,
   * we have to stash that value someplace before the next bytes arive
   * that complete the decoding */
  union {
    uint64_t num;
    struct {
      size_t remaining;
      size_t length_of_length;
    } tag;
    struct {
      uint64_t num;
      size_t count_num;
      size_t state;
      size_t last_id;
    } oid;
    struct {
      unsigned state;
      unsigned year : 7;
      unsigned month : 4;
      unsigned day : 5;
      unsigned hour : 5;
      unsigned minute : 6;
      unsigned second : 6;
    } timestamp;
  } u;
};

size_t convert_oid(unsigned char *dst, size_t sizeof_dst, const char *src);
size_t asn1_length(const unsigned char *px, size_t length, size_t *r_offset);
size_t asn1_integer(const unsigned char *px, size_t length, size_t *r_offset);
unsigned asn1_tag(const unsigned char *px, size_t length, size_t *r_offset);

void ASN1_push(struct ASN1Decode *x, unsigned next_state, size_t remaining);
unsigned ASN1_pop(struct ASN1Decode *x);
bool ASN1_skip(struct ASN1Decode *x, size_t *i, size_t length);

#endif