#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"
#include "masscan-app.h"
#include "proto-asn1.h"
#include "proto-banout.h"
#include "proto-spnego.h"
#include "smack.h"
#include "string_s.h"

static struct SMACK *smack_spnego_oids;
static struct SpnegoOid {
  const char *oid;
  const char *name;
} spnego_oids[] = {
    {"42", "1.2"},
    {"42.840", "1.2.840"},
    {"42.840.48018", "1.2.840.48018"},
    {"42.840.48018.1", "1.2.840.48018.1"},
    {"42.840.48018.1.2", "1.2.840.48018.1.2"},
    {"42.840.48018.1.2.2", "MS KRB5 - Microsoft Kerberos 5"},
    {"42.840.113554", "1.2.840.113554"},
    {"42.840.113554.1", "1.2.840.113554.1"},
    {"42.840.113554.1.2", "1.2.840.113554.1.2"},
    {"42.840.113554.1.2.2", "KRB5 - Kerberos 5"},
    {"42.840.113554.1.2.2.3", "KRB5 - Kerberos 5 - User to User"},
    {"43", "1.3"},
    {"43.6", "1.3.6"},
    {"43.6.1", "1.3.6.1"},
    {"43.6.1.4", "1.3.6.1.4"},
    {"43.6.1.4.1", "1.3.6.1.4.1"},
    {"43.6.1.4.1.311", "1.3.6.1.4.311"},
    {"43.6.1.4.1.311.2", "1.3.6.1.4.311.2"},
    {"43.6.1.4.1.311.2.2", "1.3.6.1.4.311.2.2"},
    {"43.6.1.4.1.311.2.2.10",
     "NTLMSSP - Microsoft NTLM Security Support Provider"},
    {"43.6.1.4.1.311.2.2.30",
     "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"},
    {0, 0},
};

void spnego_init(void) {
  size_t i;

  /* We use an Aho-Corasick pattern matcher for this. Not necessarily
   * the most efficient, but also not bad */
  smack_spnego_oids = smack_create("spnego-oids", 0);

  /* We just go through the table of OIDs and add them all one by
   * one */
  for (i = 0; spnego_oids[i].name; i++) {
    unsigned char pattern[256];
    size_t len;

    len = convert_oid(pattern, sizeof(pattern), spnego_oids[i].oid);
    smack_add_pattern(smack_spnego_oids, pattern, len, i,
                      SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK);
  }

  /* Now that we've added all the OIDs, we need to compile this into
   * an efficientdata structure. Later, when we get packets, we'll
   * use this for searching */
  smack_compile(smack_spnego_oids);
}

void spnego_decode(struct SpnegoDecode *spnego, const unsigned char *px,
                   size_t length, struct BannerOutput *banout) {

  struct ASN1Decode *x = &spnego->asn1;
  size_t i;

  enum spnegoState {
    InitialContextToken_tag,
    negotiationToken_tag,
    thisMech_tag,
    negTokenInit_tag,
    negTokenInit_sec,
    negTokenInit_mechTypes_tag,
    negTokenInit_mechTypes_sec,
    negTokenInit_mechType_tag,
    negTokenInit_mechType_content,
    negTokenInit_mechType_content2,
    negTokenInit_reqFlags_tag,
    negTokenInit_mechToken_tag,
    negTokenInit_mechToken_content,
    negTokenInit_mechToken_content2,
    negTokenInit_mechListMIC_tag,

    negTokenResp_tag,
    negTokenResp_sec,
    negTokenResp_choice,
    negTokenResp_negState_tag,
    negTokenResp_supportedMech_tag,
    negTokenResp_responseToken_tag,
    negTokenResp_responseToken_content,
    negTokenResp_responseToken_content2,
    negTokenResp_mechListMIC_tag,

    len,
    lenlen,
    UnknownContents,
  };

  enum spnegoState state = x->state;

  /* for all bytes in the current fragment ...
   * process that byte, causing a state-transition */
  for (i = 0; i < length; i++) {

    /* Decrement the current 'remaining' length field. */
    x->stack.remainings[0]--;

    /* Jump to the current current state */
    switch (state) {
    case InitialContextToken_tag:
      if (px[i] == 0x60) {
        // section-3.1 https://datatracker.ietf.org/doc/html/rfc2743
        x->brother_state = UnknownContents;
        x->child_state = thisMech_tag;
        state = len;
        break;
      }
      // state = negotiationToken_tag;
      /* fall through */
    case negotiationToken_tag:
      /* NegotiationToken ::= CHOICE {
           negTokenInit    [0] NegTokenInit,
           negTokenResp    [1] NegTokenResp } */
      x->brother_state = InitialContextToken_tag;
      switch (px[i]) {
      case 0xa0:
        x->child_state = negTokenInit_tag;
        break;
      case 0xa1:
        x->child_state = negTokenResp_tag;
        break;
      default:
        x->child_state = UnknownContents;
        break;
      }
      state = len;
      break;

    case thisMech_tag:
      x->brother_state = negotiationToken_tag;
      x->child_state = UnknownContents;
      state = len;
      break;

    case negTokenInit_tag:
      if (px[i] == 0x30) {
        x->brother_state = negotiationToken_tag;
        x->child_state = negTokenInit_sec;
      } else {
        x->brother_state = UnknownContents;
        x->child_state = UnknownContents;
      }
      state = len;
      break;

    case negTokenInit_sec:
      /* NegTokenInit ::= SEQUENCE {
           mechTypes       [0] MechTypeList,
           reqFlags        [1] ContextFlags  OPTIONAL,
           -- inherited from RFC 2478 for backward compatibility,
           -- RECOMMENDED to be left out
           mechToken       [2] OCTET STRING  OPTIONAL,
           mechListMIC     [3] OCTET STRING  OPTIONAL,
           ... } */
      x->brother_state = negTokenInit_tag;
      switch (px[i]) {
      case 0xa0:
        x->child_state = negTokenInit_mechTypes_tag;
        break;
      case 0xa1:
        x->child_state = negTokenInit_reqFlags_tag;
        break;
      case 0xa2:
        x->child_state = negTokenInit_mechToken_tag;
        break;
      case 0xa3:
        x->child_state = negTokenInit_mechListMIC_tag;
        break;
      default:
        x->child_state = UnknownContents;
        break;
      }
      state = len;
      break;
    case negTokenInit_mechListMIC_tag:
    case negTokenInit_reqFlags_tag:
      x->brother_state = negTokenInit_sec;
      x->child_state = UnknownContents;
      state = len;
      break;
    case negTokenInit_mechToken_tag:
      x->brother_state = negTokenInit_sec;
      x->child_state = negTokenInit_mechToken_content;
      state = len;
      break;
    case negTokenInit_mechToken_content:
      state = negTokenInit_mechToken_content2;
      /* fall through */
    case negTokenInit_mechToken_content2:
      break;
    case negTokenInit_mechTypes_tag:
      /* MechTypeList :: = SEQUENCE OF MechType */
      if (px[i] == 0x30) {
        x->brother_state = negTokenInit_sec;
        x->child_state = negTokenInit_mechTypes_sec;
      } else {
        x->brother_state = UnknownContents;
        x->child_state = UnknownContents;
      }
      state = len;
      break;
    case negTokenInit_mechTypes_sec:
      // state = negTokenInit_mechType_tag;
      /* fall through */
    case negTokenInit_mechType_tag:
      /* MechType ::= OBJECT IDENTIFIER */
      if (px[i] == 0x06) {
        x->brother_state = negTokenInit_mechTypes_sec;
        x->child_state = negTokenInit_mechType_content;
      } else {
        x->brother_state = UnknownContents;
        x->child_state = UnknownContents;
      }
      state = len;
      break;
    case negTokenInit_mechType_content:
      state = negTokenInit_mechType_content2;
      if (!spnego->is_printed_mech_types) {
        memset(&x->u.oid, 0, sizeof(x->u.oid));
        x->u.oid.last_id = SMACK_NOT_FOUND;
        if (spnego->count_mech_types == 0) {
          banout_append(banout, PROTO_SMB, " MechTypes[", AUTO_LEN);
        } else {
          banout_append(banout, PROTO_SMB, ", ", AUTO_LEN);
        }
      }
      /* fall through */
    case negTokenInit_mechType_content2:
      if (!spnego->is_printed_mech_types) {
        size_t id;
        size_t offset = i;
        size_t oid_state = x->u.oid.state;
        id = smack_search_next(smack_spnego_oids, &oid_state, px, &offset,
                               offset + 1);
        x->u.oid.state = oid_state;
        x->u.oid.num <<= 7;
        x->u.oid.num |= px[i] & 0x7F;

        if (x->stack.remainings[0] == 0) {
          if (id != SMACK_NOT_FOUND) {
            banout_append(banout, PROTO_SMB, spnego_oids[id].name, AUTO_LEN);
          }
          spnego->count_mech_types += 1;
        }
        if ((px[i] & 0x80) == 0) {
          if (id == SMACK_NOT_FOUND) {
            char buf[64];
            if (x->u.oid.last_id != SMACK_NOT_FOUND) {
              banout_append(banout, PROTO_SMB,
                            spnego_oids[x->u.oid.last_id].name, AUTO_LEN);
            }
            if (x->u.oid.count_num == 0) {
              uint64_t sid0, sid1;
              sid0 = x->u.oid.num / 40;
              if (sid0 > 2) {
                sid0 = 2;
              }
              sid1 = x->u.oid.num - sid0 * 40;
              sprintf_s(buf, sizeof(buf), "%" PRIu64 ".%" PRIu64, sid0, sid1);
            } else {
              sprintf_s(buf, sizeof(buf), ".%" PRIu64, x->u.oid.num);
            }

            banout_append(banout, PROTO_SMB, buf, AUTO_LEN);
          }
          x->u.oid.last_id = id;
          x->u.oid.num = 0;
          x->u.oid.count_num += 1;
        }
      }
      break;

    case negTokenResp_tag:
      if (px[i] == 0x30) {
        x->brother_state = negotiationToken_tag;
        x->child_state = negTokenResp_sec;
      } else {
        x->brother_state = UnknownContents;
        x->child_state = UnknownContents;
      }
      state = len;
      break;
    case negTokenResp_sec:
      // state = negTokenResp_choice;
      /* fall through */
    case negTokenResp_choice:
      /* NegTokenResp ::= SEQUENCE {
           negState       [0] ENUMERATED {
             accept-completed    (0),
             accept-incomplete   (1),
             reject              (2),
             request-mic         (3) } OPTIONAL,
         -- REQUIRED in the first reply from the target
         supportedMech   [1] MechType      OPTIONAL,
         -- present only in the first reply from the target
         responseToken   [2] OCTET STRING  OPTIONAL,
         mechListMIC     [3] OCTET STRING  OPTIONAL,
         ... }*/
      x->brother_state = negTokenResp_sec;
      switch (px[i]) {
      case 0xa0:
        x->child_state = negTokenResp_negState_tag;
        break;
      case 0xa1:
        x->child_state = negTokenResp_supportedMech_tag;
        break;
      case 0xa2:
        x->child_state = negTokenResp_responseToken_tag;
        break;
      case 0xa3:
        x->child_state = negTokenResp_mechListMIC_tag;
        break;
      default:
        x->child_state = UnknownContents;
        break;
      }
      state = len;
      break;
    case negTokenResp_negState_tag:
    case negTokenResp_supportedMech_tag:
    case negTokenResp_mechListMIC_tag:
      x->brother_state = negTokenResp_choice;
      x->child_state = UnknownContents;
      state = len;
      break;
    case negTokenResp_responseToken_tag:
      x->brother_state = negTokenResp_choice;
      x->child_state = negTokenResp_responseToken_content;
      state = len;
      break;
    case negTokenResp_responseToken_content:
      if (spnego->ntlmssp.buf) {
        ntlmssp_cleanup(&spnego->ntlmssp);
      }
      ntlmssp_decode_init(&spnego->ntlmssp, x->stack.remainings[0] + 1);
      // state = negTokenResp_responseToken_content2;
      /* fall through */
    case negTokenResp_responseToken_content2: {
      size_t new_max = length - i;

      if (new_max > x->stack.remainings[0] + 1) {
        new_max = x->stack.remainings[0] + 1;
      }

      ntlmssp_decode(&spnego->ntlmssp, px + i, new_max, banout);

      x->stack.remainings[0] -= new_max - 1;
      if (x->stack.remainings[0] == 0) {
        if (spnego->ntlmssp.buf) {
          free(spnego->ntlmssp.buf);
        }
      }
    } break;

    case len:
      /* We do the same processing for all the various length fields.
       * There are three possible length fields:
       * 0x7F - for lengths 127 and below
       * 0x81 XX - for lengths 127 to 255
       * 0x82 XX XX - for length 256 to 65535
       * This state processes the first byte, and if it's an extended
       * field, switches to the corresponding xxx_LENLEN state */
      if (px[i] & 0x80) {
        x->u.tag.length_of_length = px[i] & 0x7F;
        x->u.tag.remaining = 0;
        state = lenlen;
      } else {
        x->u.tag.remaining = px[i];
        ASN1_push(x, x->brother_state, x->u.tag.remaining);
        state = x->child_state;
        memset(&x->u, 0, sizeof(x->u));
      }
      break;
    case lenlen:
      /* We process all multibyte lengths the same way in this
       * state. */

      /* [ASN1-DER-LENGTH]
       * Check for strict DER compliance, which says that there should
       * be no leading zero bytes */
      if (x->u.tag.remaining == 0 && px[i] == 0)
        x->is_der_failure = 1;

      /* parse this byte */
      x->u.tag.remaining = (x->u.tag.remaining) << 8 | px[i];
      x->u.tag.length_of_length--;

      /* If we aren't finished yet, loop around and grab the next */
      if (x->u.tag.length_of_length)
        break;

      /* [ASN1-DER-LENGTH]
       * Check for strict DER compliance, which says that for lengths
       * 127 and below, we need only 1 byte to encode it, not many */
      if (x->u.tag.remaining < 128)
        x->is_der_failure = 1;

      /*
       * We have finished parsing the tag-length fields, and are now
       * ready to parse the 'value'. Push the current state on the
       * stack, then descend into the child field.
       */
      ASN1_push(x, x->brother_state, x->u.tag.remaining);
      state = x->child_state;
      memset(&x->u, 0, sizeof(x->u));
      break;
    default:;
    }

    /* If we've reached the end of the current field, then we need to
     * pop up the stack and resume parsing the parent field. Since we
     * reach the end of several levels simultaneously, we may need to
     * pop several levels at once */
    while (x->stack.remainings[0] == 0) {
      if (x->stack.depth == 0) {
        return;
      }
      if (state == negTokenInit_mechTypes_sec) {
        if (!spnego->is_printed_mech_types) {
          banout_append(banout, PROTO_SMB, "]", AUTO_LEN);
          spnego->count_mech_types = 0;
          spnego->is_printed_mech_types = 1;
        }
      }

      state = ASN1_pop(x);
    }
  }
}

void spnego_decode_init(struct SpnegoDecode *x, size_t length) {
  memset(x, 0, sizeof(*x));
  x->asn1.stack.remainings[0] = length;
}

int spnego_selftest(void) {
  int x = 0;

  {
    bool check;
    static const unsigned char bytes[] = {
        0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0,
        0x1e, 0x30, 0x1c, 0xa0, 0x1a, 0x30, 0x18, 0x06, 0x0a, 0x2b, 0x06,
        0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e, 0x06, 0x0a, 0x2b,
        0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
    struct BannerOutput banout[1];
    struct SpnegoDecode spnego[1];

    banout_init(banout);
    spnego_decode_init(spnego, sizeof(bytes));
    spnego_decode(spnego, bytes, sizeof(bytes), banout);

    if (spnego[0].asn1.is_der_failure != false) {
      LOG(LEVEL_ERROR, "[-] spnego.selftest: ans1 fail parse %d\n", __LINE__);
      x += 1;
    }
    check = banout_is_contains(
        banout, PROTO_SMB,
        "MechTypes["
        "NEGOEX - SPNEGO Extended Negotiation Security Mechanism, "
        "NTLMSSP - Microsoft NTLM Security Support Provider]");
    if (!check) {
      LOG(LEVEL_ERROR, "MechTypes(name) not found\n");
      x += 1;
    }

    banout_release(banout);
  }

  {
    bool check;
    static const unsigned char bytes[] = {
        0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0,
        0x1e, 0x30, 0x1c, 0xa0, 0x1a, 0x30, 0x18, 0x06, 0x0a, 0x01, 0x06,
        0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e, 0x06, 0x0a, 0x2b,
        0x06, 0x01, 0x02, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
    struct BannerOutput banout[1];
    struct SpnegoDecode spnego[1];

    banout_init(banout);
    spnego_decode_init(spnego, sizeof(bytes));
    spnego_decode(spnego, bytes, sizeof(bytes), banout);

    if (spnego[0].asn1.is_der_failure != false) {
      LOG(LEVEL_ERROR, "[-] spnego.selftest: ans1 fail parse %d\n", __LINE__);
      x += 1;
    }
    check =
        banout_is_contains(banout, PROTO_SMB,
                           "MechTypes["
                           "0.1.6.1.4.1.311.2.2.30, 1.3.6.1.2.1.311.2.2.10]");
    if (!check) {
      LOG(LEVEL_ERROR, "MechTypes(OID) not found\n");
      x += 1;
    }

    banout_release(banout);
  }

  {
    bool check;
    static const unsigned char bytes[] = {
        0xa1, 0x81, 0xba, 0x30, 0x81, 0xb7, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1,
        0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02,
        0x0a, 0xa2, 0x81, 0xa1, 0x04, 0x81, 0x9e, 0x4e, 0x54, 0x4c, 0x4d, 0x53,
        0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x38,
        0x00, 0x00, 0x00, 0x15, 0x82, 0x8a, 0x62, 0xb3, 0x7b, 0xf1, 0x86, 0x27,
        0x9b, 0x69, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58,
        0x00, 0x58, 0x00, 0x46, 0x00, 0x00, 0x00, 0x06, 0x01, 0xb1, 0x1d, 0x00,
        0x00, 0x00, 0x0f, 0x44, 0x00, 0x55, 0x00, 0x44, 0x00, 0x45, 0x00, 0x4e,
        0x00, 0x45, 0x00, 0x57, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x44, 0x00, 0x55,
        0x00, 0x44, 0x00, 0x45, 0x00, 0x4e, 0x00, 0x45, 0x00, 0x57, 0x00, 0x01,
        0x00, 0x0e, 0x00, 0x44, 0x00, 0x55, 0x00, 0x44, 0x00, 0x45, 0x00, 0x4e,
        0x00, 0x45, 0x00, 0x57, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x44, 0x00, 0x75,
        0x00, 0x64, 0x00, 0x65, 0x00, 0x4e, 0x00, 0x65, 0x00, 0x77, 0x00, 0x03,
        0x00, 0x0e, 0x00, 0x44, 0x00, 0x75, 0x00, 0x64, 0x00, 0x65, 0x00, 0x4e,
        0x00, 0x65, 0x00, 0x77, 0x00, 0x07, 0x00, 0x08, 0x00, 0x0e, 0x25, 0x4d,
        0xc0, 0xc1, 0x1c, 0xd8, 0x01, 0x00, 0x00, 0x00, 0x00};
    struct BannerOutput banout[1];
    struct SpnegoDecode spnego[1];

    banout_init(banout);
    spnego_decode_init(spnego, sizeof(bytes));
    spnego_decode(spnego, bytes, sizeof(bytes), banout);

    if (spnego[0].asn1.is_der_failure != false) {
      LOG(LEVEL_ERROR, "[-] spnego.selftest: ans1 fail parse %d\n", __LINE__);
      x += 1;
    }
    check = true;
    check &= banout_is_contains(banout, PROTO_SMB, "domain=DUDENEW");
    check &= banout_is_contains(banout, PROTO_SMB, "version=6.1.7601");
    check &= banout_is_contains(banout, PROTO_SMB, "ntlm-ver=15");
    check &= banout_is_contains(banout, PROTO_SMB, "domain=DUDENEW");
    check &= banout_is_contains(banout, PROTO_SMB, "name=DUDENEW");
    check &= banout_is_contains(banout, PROTO_SMB, "domain-dns=DudeNew");
    check &= banout_is_contains(banout, PROTO_SMB, "name-dns=DudeNew");
    if (!check) {
      LOG(LEVEL_ERROR, "Fail decode ntlmssp\n");
      x += 1;
    }
    banout_release(banout);
  }

  if (x) {
    LOG(LEVEL_ERROR, "spnego failure\n");
    return 1;
  }

  return 0;
}