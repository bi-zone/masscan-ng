#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"
#include "proto-asn1.h"
#include "util-cross.h"

#define TWO_BYTE ((unsigned long long)(~0) << 7)
#define THREE_BYTE ((unsigned long long)(~0) << 14)
#define FOUR_BYTE ((unsigned long long)(~0) << 21)
#define FIVE_BYTE ((unsigned long long)(~0) << 28)

/****************************************************************************
 * Used in converting text object-ids into their binary form.
 * @see convert_oid()
 ****************************************************************************/
size_t id_prefix_count(size_t id) {
  if (id & FIVE_BYTE)
    return 4;
  if (id & FOUR_BYTE)
    return 3;
  if (id & THREE_BYTE)
    return 2;
  if (id & TWO_BYTE)
    return 1;
  return 0;
}

/****************************************************************************
 * Convert text OID to binary
 ****************************************************************************/
size_t convert_oid(unsigned char *dst, size_t sizeof_dst, const char *src) {
  size_t offset = 0;

  /* 'for all text characters' */
  while (*src) {
    char *next_src;
    size_t id;
    size_t count;
    size_t i;

    /* skip to next number */
    while (*src == '.') {
      src++;
    }

    /* parse integer */
    id = strtoul(src, &next_src, 0);
    if (src == next_src) {
      /* invalid integer, programming error */
      break;
    }

    src = next_src;

    /* find length of the integer */
    count = id_prefix_count(id);

    /* add binary integer to pattern */
    for (i = count; i > 0; i--) {
      if (offset < sizeof_dst) {
        dst[offset++] = ((id >> (7 * i)) & 0x7F) | 0x80;
      }
    }
    if (offset < sizeof_dst) {
      dst[offset++] = (id & 0x7F);
    }
  }

  return offset;
}

/****************************************************************************
 * An ASN.1 length field has two formats.
 *  - if the high-order bit of the length byte is clear, then it
 *    encodes a length between 0 and 127.
 *  - if the high-order bit is set, then the length byte is a
 *    length-of-length, where the low order bits dictate the number of
 *    remaining bytes to be used in the length.
 ****************************************************************************/
size_t asn1_length(const unsigned char *px, size_t length, size_t *r_offset) {

  size_t result;

  /* check for errors */
  if ((*r_offset >= length) ||
      ((px[*r_offset] & 0x80) &&
       ((*r_offset) + (px[*r_offset] & 0x7F) >= length))) {
    *r_offset = length;
    return UINTPTR_MAX;
  }

  /* grab the byte's value */
  result = px[(*r_offset)++];

  if (result & 0x80) {
    unsigned length_of_length = result & 0x7F;
    if (length_of_length == 0) {
      *r_offset = length;
      return UINTPTR_MAX;
    }
    result = 0;
    while (length_of_length) {
      result = result * 256 + px[(*r_offset)++];
      if (result > 0x10000) {
        *r_offset = length;
        return UINTPTR_MAX;
      }
      length_of_length--;
    }
  }

  return result;
}

/****************************************************************************
 * Extract an integer. Note
 ****************************************************************************/
size_t asn1_integer(const unsigned char *px, size_t length, size_t *r_offset) {
  size_t int_length;
  size_t result;

  if (px[(*r_offset)++] != 0x02) {
    *r_offset = length;
    return UINT64_MAX;
  }

  int_length = asn1_length(px, length, r_offset);
  if (int_length == UINTPTR_MAX) {
    *r_offset = length;
    return UINT64_MAX;
  }
  if (*r_offset + int_length > length) {
    *r_offset = length;
    return UINT64_MAX;
  }
  if (int_length > 20) {
    *r_offset = length;
    return UINT64_MAX;
  }

  result = 0;
  while (int_length--)
    result = result * 256 + px[(*r_offset)++];

  return result;
}

/****************************************************************************
 ****************************************************************************/
unsigned asn1_tag(const unsigned char *px, size_t length, size_t *r_offset) {
  if (*r_offset >= length) {
    return 0;
  }
  return px[(*r_offset)++];
}

/****************************************************************************
 * Since ASN.1 contains nested structures, each with their own length field,
 * we must maintain a small stack as we parse down the structure. Every time
 * we enter a field, this function "pushes" the ASN.1 "length" field onto
 * the stack. When we are done parsing the current field, we'll pop the
 * length back off the stack, and subtract from it the number of bytes
 * we've parsed.
 *
 * @param x
 *      The X.509 certificate parsing structure.
 * @param next_state
 *      Tells the parser the next field we'll be parsing after this field
 *      at the same level of the nested ASN.1 structure, or nothing if
 *      there are no more fields.
 * @param remaining
 *      The 'length' field. We call it 'remaining' instead of 'length'
 *      because as more bytes arrive, we decrement the length field until
 *      it reaches zero. Thus, at any point of time, it doesn't represent
 *      the length of the current ASN.1 field, but the remaining-length.
 ****************************************************************************/
void ASN1_push(struct ASN1Decode *x, unsigned next_state, size_t remaining) {

  static const size_t STACK_DEPTH = ARRAY_SIZE(x->stack.remainings);

  /* X.509 certificates can't be more than 64k in size. Therefore, to
   * conserve space (as we must store the state for millions of TCP
   * connections), we use the smallest number possible for the length,
   * meaning a 16-bit 'unsigned short'. If the certificate has a larger
   * length field, we need to reject it. */
  if ((remaining >> 16) != 0) {
    LOG(LEVEL_WARNING, "ASN.1 length field too big\n");
    x->state = STATE_ASN1_ERROR;
    return;
  }

  /* Make sure we don't recurse too deep, past the end of the stack. Note
   * that this condition checks a PRGRAMMING error not an INPUT error,
   * because we skip over fields we don't care about, and don't recurse
   * into them even if they have many levels deep */
  if (x->stack.depth >= STACK_DEPTH) {
    LOG(LEVEL_WARNING, "ASN.1 recursion too deep\n");
    x->state = STATE_ASN1_ERROR;
    return;
  }

  /* Subtract this length from it's parent.
   *
   *[ASN1-CHILD-OVERFLOW]
   * It is here that we deal with the classic ASN.1 parsing problem in
   * which the child object claims a bigger length than its parent
   * object. We could shrink the length field to fit, then continue
   * parsing, but instead we choose to instead cease parsing the certificate.
   * Note that this property is recursive: I don't need to redo the check
   * all the way up the stack, because I know my parent's length does
   * not exceed my grandparent's length.
   * I know certificates exist that trigger this error -- I need to track
   * them down and figure out why.
   */
  if (x->stack.depth) {
    if (remaining > x->stack.remainings[0]) {
      LOG(LEVEL_INFO, "ASN.1 inner object bigger than container [%u, %u]\n",
          next_state, x->stack.states[0]);
      x->state = STATE_ASN1_ERROR;
      return;
    }
    x->stack.remainings[0] = x->stack.remainings[0] - remaining;
  }

  /* Since 'remainings[0]' always represents the top of the stack, we
   * move all the bytes down one during the push operation. I suppose this
   * is more expensive than doing it the other way, where something
   * like "raminings[stack.depth]" represents the top of the stack,
   * meaning no moves are necessary, but I prefer the cleanliness of the
   * code using [0] index instead */
  memmove(&x->stack.remainings[1], &x->stack.remainings[0],
          x->stack.depth * sizeof(x->stack.remainings[0]));
  x->stack.remainings[0] = remaining;

  memmove(&x->stack.states[1], &x->stack.states[0],
          x->stack.depth * sizeof(x->stack.states[0]));
  x->stack.states[0] = next_state;

  /* increment the count by one and exit */
  x->stack.depth++;
}

/****************************************************************************
 * This is the corresponding 'pop' operation to the ASN1_push() operation.
 * See that function for more details.
 * @see ASN1_push()
 ****************************************************************************/
unsigned ASN1_pop(struct ASN1Decode *x) {
  unsigned next_state;
  next_state = x->stack.states[0];
  x->stack.depth--;
  memmove(&x->stack.remainings[0], &x->stack.remainings[1],
          x->stack.depth * sizeof(x->stack.remainings[0]));
  memmove(&x->stack.states[0], &x->stack.states[1],
          x->stack.depth * sizeof(x->stack.states[0]));
  return next_state;
}

/****************************************************************************
 * Called to skip the remainder of the ASN.1 field
 * @return
 *      true - if we've reached the end of the field
 *      false - otherwise
 ****************************************************************************/
bool ASN1_skip(struct ASN1Decode *x, size_t *i, size_t length) {

  size_t len;

  if (x->stack.remainings[0] == 0)
    return 1;

  /* bytes remaining in packet */
  len = length - (*i) - 1;

  /* bytes remaining in field */
  if (len > x->stack.remainings[0])
    len = (size_t)x->stack.remainings[0];

  /* increment 'offset' by this length */
  (*i) += len;

  /* decrement 'remaining' by this length */
  x->stack.remainings[0] = x->stack.remainings[0] - len;

  return x->stack.remainings[0] == 0;
}
