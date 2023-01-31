/*
    !!!!! BIZZARE CODE ALERT !!!!

    This module decodes X.509 public-key certificates using a
    "state-machine parser". If you are unfamiliar with such parsers,
    this will look very strange to you.

    The reason for such parsers is scalability. Certificates are so big
    that they typically cross packet boundaries. This requires some sort
    of "reassembly", which in term requires "memory allocation". This
    is done on a per-connection basis, resulting in running out of memory
    when dealing with millions of connections.

    With a state-machine parser, we don't need to reassemble certificates, or
    allocate memory. Instead, we maintain "state" between fragments. There
    is about 60 bytes of state that we must keep.

    If you are a code reviewer, you may care about looking into these common
    ASN.1 parsing errors. I've marked them with a [NAME] here, you can search
    these strings in the code to see how they are handled.

    [ASN1-CHILD-OVERFLOW]
        when the child length field causes it to exceed the length of
        its parent
    [ASN1-CHILD-UNDERFLOW]
        when there is padding after all the child fields within a larger
        parent field
    [ASN1-DER-LENGTH]
        when there are more bits used to encode a length field than necessary,
        such as using 0x82 0x00 0x12 instead of simply 0x12 as a length
    [ASN1-DER-NUMBER]
        When there are more bits than necessary to encode an integer, such
        as 0x00 0x00 0x00 0x20 rather than just 0x20.
        Since we don't deal with numbers, we don't check this.
    [ASN1-DER-SIGNED]
        issues with signed vs. unsigned numbers, where unsined 4 byte integers
        need an extra leading zero byte if their high-order bit is set
        Since we don't deal with numbers, we don't check this.
    [ASN1-DER-OID]
        Issues with inserting zeroes into OIDs.
        We explicitly deal with the opposite issue, allowing zeroes to be
        inserted. We should probably chainge that, and detect it as a DER
        error.

    CERTIFICATE FORMAT

    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
   CertificateSerialNumber  ::=  INTEGER
   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }
   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }
   UniqueIdentifier  ::=  BIT STRING
   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
 */
#include "proto-x509.h"
#include "logger.h"
#include "masscan-app.h"
#include "proto-banner1.h"
#include "proto-banout.h"
#include "smack.h"
#include "util-cross.h"
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/****************************************************************************
 * The X.509 certificates mark certain extensible fields with ASN.1
 * object-identifiers. Instead of copying these out of the certificate,
 * we match them using an Aho-Corasick DFA parser. These object-ids are
 * below. At program startup, the main() function must call x509_init()
 * to build the Aho-Corasick state-machine, which the main state-machine
 * will use to parse these object-ids.
 ****************************************************************************/
static struct SMACK *smack_ssl_oids;

/****************************************************************************
 * Currently, the only field we extract is the "Common Name".
 ****************************************************************************/
enum {
  Subject_Unknown,
  Subject_Common,
};

static struct SslOid {
  const char *oid;
  const char *name;
  int id;
} ssl_oids[] = {
    {"42", "1.2"},
    {"42.840", "1.2.840"},
    {"42.840.52", "0"},
    {"42.840.113549", "1.2.840.113549"},
    {"42.840.113549.1", "1.2.840.113549.1"},
    {"42.840.113549.1.1", "1.2.840.113549.1.1"},
    {"42.840.113549.1.1.4", "md5WithRSAEncryption"},
    {"42.840.113549.1.1.5", "shaWithRSAEncryption"},
    {"42.840.113549.1.1.11", "sha256WithRSAEncryption"},
    {"42.840.113549.1.9", "1.2.840.113549.1.9"},
    {"42.840.113549.1.9.1", "email"},
    {"85", "2.5"},
    {"85.4", "2.5.4"},
    {"85.4.3", "common", Subject_Common},
    {"85.4.5", "serial"},
    {"85.4.6", "country"},
    {"85.4.7", "locality"},
    {"85.4.8", "state"},
    {"85.4.10", "organization"},
    {"85.4.11", "unit"},
    {"85.4.13", "description"},
    {"85.29", "2.5.29"},
    {"85.29.17", "altname", Subject_Common},
    {0, 0},
};

/****************************************************************************
 * We need to initialize the OID parser
 * This should be called on program startup.
 * This is so that we can show short names, like "sysName", rather than
 * the entire OID.
 ****************************************************************************/
void x509_init(void) {
  size_t i;

  /* We use an Aho-Corasick pattern matcher for this. Not necessarily
   * the most efficient, but also not bad */
  smack_ssl_oids = smack_create("ssl-oids", 0);

  /* We just go through the table of OIDs and add them all one by
   * one */
  for (i = 0; ssl_oids[i].name; i++) {
    unsigned char pattern[256];
    size_t len;

    len = convert_oid(pattern, sizeof(pattern), ssl_oids[i].oid);
    smack_add_pattern(smack_ssl_oids, pattern, len, i,
                      SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK);
  }

  /* Now that we've added all the OIDs, we need to compile this into
   * an efficientdata structure. Later, when we get packets, we'll
   * use this for searching */
  smack_compile(smack_ssl_oids);
}

/****************************************************************************
 * The X.509 ASN.1 parser is done with a state-machine, where each byte of
 * the certificate has a corresponding state value. This massive enum
 * is for all those states.
 * DANGER NOTE NOTE NOTE NOTE DANGER NOTE DANGER NOTE
 *  These states are in a specific order. We'll just do 'state++' sometimes
 *  to go the next state. Therefore, you can't change the order without
 *  changing the code.
 ****************************************************************************/
enum X509state {
  TAG0,
  TAG0_LEN,
  TAG0_LENLEN,
  TAG1,
  TAG1_LEN,
  TAG1_LENLEN,
  VERSION0_TAG,
  VERSION0_LEN,
  VERSION0_LENLEN,
  VERSION1_TAG,
  VERSION1_LEN,
  VERSION1_LENLEN,
  VERSION_CONTENTS,
  SERIAL_TAG,
  SERIAL_LEN,
  SERIAL_LENLEN,
  SERIAL_CONTENTS,
  SIG0_TAG,
  SIG0_LEN,
  SIG0_LENLEN,
  SIG1_TAG,
  SIG1_LEN,
  SIG1_LENLEN,
  SIG1_CONTENTS0,
  SIG1_CONTENTS1,
  ISSUER0_TAG,
  ISSUER0_LEN,
  ISSUER0_LENLEN,
  ISSUER1_TAG,
  ISSUER1_LEN,
  ISSUER1_LENLEN,
  ISSUER2_TAG,
  ISSUER2_LEN,
  ISSUER2_LENLEN,
  ISSUERID_TAG,
  ISSUERID_LEN,
  ISSUERID_LENLEN,
  ISSUERID_CONTENTS0,
  ISSUERID_CONTENTS1,
  ISSUERNAME_TAG,
  ISSUERNAME_LEN,
  ISSUERNAME_LENLEN,
  ISSUERNAME_CONTENTS,
  VALIDITY_TAG,
  VALIDITY_LEN,
  VALIDITY_LENLEN,
  VNBEFORE_TAG,
  VNBEFORE_LEN,
  VNBEFORE_LENLEN,
  VNBEFORE_CONTENTS,
  VNAFTER_TAG,
  VNAFTER_LEN,
  VNAFTER_LENLEN,
  VNAFTER_CONTENTS,
  SUBJECT0_TAG,
  SUBJECT0_LEN,
  SUBJECT0_LENLEN,
  SUBJECT1_TAG,
  SUBJECT1_LEN,
  SUBJECT1_LENLEN,
  SUBJECT2_TAG,
  SUBJECT2_LEN,
  SUBJECT2_LENLEN,
  SUBJECTID_TAG,
  SUBJECTID_LEN,
  SUBJECTID_LENLEN,
  SUBJECTID_CONTENTS0,
  SUBJECTID_CONTENTS1,
  SUBJECTNAME_TAG,
  SUBJECTNAME_LEN,
  SUBJECTNAME_LENLEN,
  SUBJECTNAME_CONTENTS,
  PUBKEY0_TAG,
  PUBKEY0_LEN,
  PUBKEY0_LENLEN,
  PUBKEY0_CONTENTS,
  EXTENSIONS_A_TAG,
  EXTENSIONS_A_LEN,
  EXTENSIONS_A_LENLEN,
  EXTENSIONS_S_TAG,
  EXTENSIONS_S_LEN,
  EXTENSIONS_S_LENLEN,
  EXTENSION_TAG,
  EXTENSION_LEN,
  EXTENSION_LENLEN,
  EXTENSION_ID_TAG,
  EXTENSION_ID_LEN,
  EXTENSION_ID_LENLEN,
  EXTENSION_ID_CONTENTS0,
  EXTENSION_ID_CONTENTS1,
  EXTVALUE_TAG,
  EXTVALUE_LEN,
  EXTVALUE_LENLEN,
  EXTVALUE2_TAG,
  EXTVALUE2_LEN,
  EXTVALUE2_LENLEN,
  EXTVALUE3_TAG,
  EXTVALUE3_LEN,
  EXTVALUE3_LENLEN,
  EXT_DNSNAME_TAG,
  EXT_DNSNAME_LEN,
  EXT_DNSNAME_LENLEN,
  EXT_DNSNAME_CONTENTS,
  ALGOID0_TAG,
  ALGOID0_LEN,
  ALGOID0_LENLEN,
  ALGOID1_TAG,
  ALGOID1_LEN,
  ALGOID1_LENLEN,
  ALGOID1_CONTENTS0,
  ALGOID1_CONTENTS1,
  ENC_TAG,
  ENC_LEN,
  ENC_LENLEN,
  ENC_CONTENTS,

  PADDING = 254,
  ERROR = STATE_ASN1_ERROR
};

/****************************************************************************
 * My parser was kludged together in a couple of hours, and has this bug
 * where I really don't know the next state like I should. Therefore, this
 * function patches it, converting the next state I think I want to the
 * next state that I really do want.
 * TODO: fix the parser so that this function is no longer necessary.
 ****************************************************************************/
static unsigned kludge_next(unsigned state) {
  switch (state) {
  case TAG1_LEN:
    return ALGOID0_TAG;
  case ALGOID0_LEN:
    return ENC_TAG;
  case SERIAL_LEN:
    return SIG0_TAG;
  case VERSION0_LEN:
    return SERIAL_TAG;
  case SIG0_LEN:
    return ISSUER0_TAG;
  case ISSUER0_LEN:
    return VALIDITY_TAG;
  case SUBJECT0_LEN:
    return PUBKEY0_TAG;
  case ISSUER1_LEN:
    return ISSUER1_TAG;
  case SUBJECT1_LEN:
    return SUBJECT1_TAG;
  case ISSUERID_LEN:
    return ISSUERNAME_TAG;
  case EXTENSION_LEN:
    return EXTENSION_TAG;
  case EXTENSION_ID_LEN:
    return EXTVALUE_TAG;
  case EXT_DNSNAME_LEN:
    return EXTVALUE3_TAG;
  case SUBJECTID_LEN:
    return SUBJECTNAME_TAG;
  case VALIDITY_LEN:
    return SUBJECT0_TAG;
  case VNBEFORE_LEN:
    return VNAFTER_TAG;
  case PUBKEY0_LEN:
    return EXTENSIONS_A_TAG;
  default:
    return PADDING;
  }
}

/****************************************************************************
 * This is a parser for X.509 certificates. It uses "state-machine"
 * technology, so that it accepts an in-order sequence of fragments. The
 * entire x.509 certificate does not need to be in memory -- you can start
 * calling this function when you have only the first fragment.
 *
 * It works by enumerating every possible state. In other words, every
 * byte of an X.509 certificate has an enumerated 'state' variable. As
 * each byte arrives from the stream, we parse it, and change to the next
 * state. When we run out of input, we exit the function, saving the
 * current state-variable. When the next fragment arrives, we resume
 * at the same state where we left off.
 ****************************************************************************/
void x509_decode(struct CertDecode *x, const unsigned char *px, size_t length,
                 struct BannerOutput *banout) {
  size_t i;
  enum X509state state = x->asn1.state;

  /* 'for all bytes in the current fragment ...'
   *   'process that byte, causing a state-transition ' */
  for (i = 0; i < length; i++) {

    /*
     * If we've reached the end of the current field, then we need to
     * pop up the stack and resume parsing the parent field. Since we
     * reach the end of several levels simultaneously, we may need to
     * pop several levels at once
     */
    while (x->asn1.stack.remainings[0] == 0) {
      if (x->asn1.stack.depth == 0)
        return;
      state = ASN1_pop(&x->asn1);
    }

    /*
     * Decrement the current 'remaining' length field.
     */
    x->asn1.stack.remainings[0]--;

    /*
     * Jump to the current current state
     */
    switch (state) {
    case ENC_TAG:
      if (px[i] != 0x03) {
        state = ERROR;
        continue;
      }
      state++;
      break;
    case ISSUERNAME_TAG:
      if (px[i] != 0x13 && px[i] != 0x0c) {
        state++;
        continue;
      }
      if (x->is_capture_issuer) {
        banout_append(banout, PROTO_SSL3, " issuer[", AUTO_LEN);
      }
      state++;
      break;
    case SUBJECTNAME_TAG:
      if (px[i] != 0x13 && px[i] != 0x0c) {
        state++;
        continue;
      }
      if (x->is_capture_subject) {
        banout_append(banout, PROTO_SSL3, " subject[", AUTO_LEN);
      }
      state++;
      break;
    case ISSUER1_TAG:
    case SUBJECT1_TAG:
      x->subject.type = 0;
      if (px[i] != 0x31) {
        state++;
        continue;
      }
      state++;
      break;
    case VNBEFORE_TAG:
    case VNAFTER_TAG:
      if (px[i] != 0x17) {
        state++;
        continue;
      }
      state++;
      break;
    case VERSION0_TAG:
      if (px[i] != 0xa0) {
        state = ERROR;
        continue;
      }
      state++;
      break;
    case SIG1_TAG:
    case ISSUERID_TAG:
    case SUBJECTID_TAG:
    case EXTENSION_ID_TAG:
    case ALGOID1_TAG:
      if (px[i] != 0x06) {
        state = ERROR;
        continue;
      }
      state++;
      break;
    case VERSION1_TAG:
    case SERIAL_TAG:
      if (px[i] != 0x02) {
        state = ERROR;
        continue;
      }
      x->asn1.u.num = 0;
      state++;
      break;
    case ISSUERNAME_CONTENTS:
      if (x->is_capture_issuer) {
        banout_append(banout, PROTO_SSL3, px + i, 1);
        if (x->asn1.stack.remainings[0] == 0)
          banout_append(banout, PROTO_SSL3, "]", 1);
      }
      break;
    case SUBJECTNAME_CONTENTS:
    case EXT_DNSNAME_CONTENTS:
      if (x->is_capture_subject) {
        banout_append(banout, PROTO_SSL3, px + i, 1);
        if (x->asn1.stack.remainings[0] == 0)
          banout_append(banout, PROTO_SSL3, "]", 1);
      } else if (x->subject.type == Subject_Common)
        banout_append(banout, PROTO_SSL3, px + i, 1);
      break;
    case VERSION_CONTENTS:
      x->asn1.u.num <<= 8;
      x->asn1.u.num |= px[i];
      if (x->asn1.stack.remainings[0] == 0)
        state = PADDING;
      break;
    case ISSUERID_CONTENTS0:
    case SUBJECTID_CONTENTS0:
    case EXTENSION_ID_CONTENTS0:
    case ALGOID1_CONTENTS0:
    case SIG1_CONTENTS0:
      memset(&x->asn1.u.oid, 0, sizeof(x->asn1.u.oid));
      state++;
      /* fall through */
    case ISSUERID_CONTENTS1:
    case SUBJECTID_CONTENTS1:
    case EXTENSION_ID_CONTENTS1:
    case ALGOID1_CONTENTS1:
    case SIG1_CONTENTS1: {
      size_t id;
      size_t offset = i;
      size_t oid_state = x->asn1.u.oid.state;

      /* First, look it up */
      id = smack_search_next(smack_ssl_oids, &oid_state, px, &offset,
                             offset + 1);
      x->asn1.u.oid.state = (unsigned short)oid_state;

      /* Do the multibyte numbers */
      x->asn1.u.oid.num <<= 7;
      x->asn1.u.oid.num |= px[i] & 0x7F;

      if (px[i] & 0x80) {
        /* This is a multibyte number, don't do anything at
         * this stage */
      } else {
        if (id != SMACK_NOT_FOUND) {
          x->subject.type = ssl_oids[id].id;
          if (x->subject.type == Subject_Common &&
              state == SUBJECTID_CONTENTS1) {
            if (x->count <= 1) {
              /* only handle first certificate in the chain */
              banout_append(banout, PROTO_SSL3, ", ", 2);
            } else {
              x->subject.type = 0;
            }
          }
          // if (x->subject.type == Subject_Common
          //                     && state == EXTENSION_ID_CONTENTS1)
          //     ; //banout_append(banout, PROTO_SSL3, ", ", 2);
        }
        x->asn1.u.oid.num = 0;
      }
      if (x->asn1.stack.remainings[0] == 0) {
        state = PADDING;
      }
    } break;
    case SERIAL_CONTENTS:
      x->asn1.stack.states[0] = (unsigned int)state + 1;
      x->asn1.u.num <<= 8;
      x->asn1.u.num |= px[i];
      if (x->asn1.stack.remainings[0] == 0)
        state = PADDING;
      break;

    case TAG0:
    case TAG1:
    case SIG0_TAG:
    case ISSUER0_TAG:
    case ISSUER2_TAG:
    case SUBJECT0_TAG:
    case SUBJECT2_TAG:
    case VALIDITY_TAG:
    case PUBKEY0_TAG:
    case EXTENSIONS_S_TAG:
    case EXTENSION_TAG:
    case EXTVALUE2_TAG:
    case ALGOID0_TAG:
      if (px[i] != 0x30) {
        state = ERROR;
        continue;
      }
      state++;
      break;
    case EXTENSIONS_A_TAG:
      if (px[i] != 0xa3) {
        state = ERROR;
        continue;
      }
      state++;
      break;

      /*
      GeneralName ::= CHOICE {
          otherName                       [0]     OtherName,
          rfc822Name                      [1]     IA5String,
          dNSName                         [2]     IA5String,
          x400Address                     [3]     ORAddress,
          directoryName                   [4]     Name,
          ediPartyName                    [5]     EDIPartyName,
          uniformResourceIdentifier       [6]     IA5String,
          iPAddress                       [7]     OCTET STRING,
          registeredID                    [8]     OBJECT IDENTIFIER }
      */

    case EXTVALUE3_TAG:
      if (x->subject.type == Subject_Common) {
        switch (px[i]) {
        case 0x82: /* dNSName */
          banout_append(banout, PROTO_SSL3, ", ", 2);
          state = EXT_DNSNAME_LEN;
          break;
        default:
          state = PADDING;
          break;
        }
      } else {
        state = PADDING;
      }
      break;

    case EXTVALUE_TAG:
      /* can be anything */
      switch (px[i]) {
      default:
      case 2:
        state = PADDING;
        break;
      case 4:
        state++;
        break;
      }
      break;

    case TAG0_LEN:
    case TAG1_LEN:
    case VERSION0_LEN:
    case VERSION1_LEN:
    case SERIAL_LEN:
    case SIG0_LEN:
    case SIG1_LEN:
    case ISSUER0_LEN:
    case ISSUER1_LEN:
    case ISSUER2_LEN:
    case ISSUERID_LEN:
    case ISSUERNAME_LEN:
    case VALIDITY_LEN:
    case VNBEFORE_LEN:
    case VNAFTER_LEN:
    case SUBJECT0_LEN:
    case SUBJECT1_LEN:
    case SUBJECT2_LEN:
    case SUBJECTID_LEN:
    case SUBJECTNAME_LEN:
    case EXTENSIONS_A_LEN:
    case EXTENSIONS_S_LEN:
    case EXTENSION_LEN:
    case EXTENSION_ID_LEN:
    case EXTVALUE_LEN:
    case EXTVALUE2_LEN:
    case EXTVALUE3_LEN:
    case EXT_DNSNAME_LEN:
    case PUBKEY0_LEN:
    case ALGOID0_LEN:
    case ALGOID1_LEN:
    case ENC_LEN:
      /* We do the same processing for all the various length fields.
       * There are three possible length fields:
       * 0x7F - for lengths 127 and below
       * 0x81 XX - for lengths 127 to 255
       * 0x82 XX XX - for length 256 to 65535
       * This state processes the first byte, and if it's an extended
       * field, switches to the corresponding xxx_LENLEN state
       */
      if (px[i] & 0x80) {
        x->asn1.u.tag.length_of_length = px[i] & 0x7F;
        x->asn1.u.tag.remaining = 0;
        state++;
      } else {
        x->asn1.u.tag.remaining = px[i];
        ASN1_push(&x->asn1, kludge_next((unsigned int)state),
                  x->asn1.u.tag.remaining);
        state += 2;
        memset(&x->asn1.u, 0, sizeof(x->asn1.u));
      }
      break;

    case TAG0_LENLEN:
    case TAG1_LENLEN:
    case VERSION0_LENLEN:
    case VERSION1_LENLEN:
    case SERIAL_LENLEN:
    case SIG0_LENLEN:
    case SIG1_LENLEN:
    case ISSUER0_LENLEN:
    case ISSUER1_LENLEN:
    case ISSUER2_LENLEN:
    case ISSUERID_LENLEN:
    case ISSUERNAME_LENLEN:
    case VALIDITY_LENLEN:
    case VNBEFORE_LENLEN:
    case VNAFTER_LENLEN:
    case SUBJECT0_LENLEN:
    case SUBJECT1_LENLEN:
    case SUBJECT2_LENLEN:
    case SUBJECTID_LENLEN:
    case SUBJECTNAME_LENLEN:
    case PUBKEY0_LENLEN:
    case EXTENSIONS_A_LENLEN:
    case EXTENSIONS_S_LENLEN:
    case EXTENSION_LENLEN:
    case EXTENSION_ID_LENLEN:
    case EXTVALUE_LENLEN:
    case EXTVALUE2_LENLEN:
    case EXTVALUE3_LENLEN:
    case EXT_DNSNAME_LENLEN:
    case ALGOID0_LENLEN:
    case ALGOID1_LENLEN:
    case ENC_LENLEN:
      /* We process all multibyte lengths the same way in this
       * state.
       */

      /* [ASN1-DER-LENGTH]
       * Check for strict DER compliance, which says that there should
       * be no leading zero bytes */
      if (x->asn1.u.tag.remaining == 0 && px[i] == 0)
        x->asn1.is_der_failure = 1;

      /* parse this byte */
      x->asn1.u.tag.remaining = (x->asn1.u.tag.remaining) << 8 | px[i];
      x->asn1.u.tag.length_of_length--;

      /* If we aren't finished yet, loop around and grab the next */
      if (x->asn1.u.tag.length_of_length)
        break;

      /* [ASN1-DER-LENGTH]
       * Check for strict DER compliance, which says that for lengths
       * 127 and below, we need only 1 byte to encode it, not many */
      if (x->asn1.u.tag.remaining < 128)
        x->asn1.is_der_failure = 1;

      /*
       * We have finished parsing the tag-length fields, and are now
       * ready to parse the 'value'. Push the current state on the
       * stack, then descend into the child field.
       */
      ASN1_push(&x->asn1, kludge_next((unsigned int)state - 1),
                x->asn1.u.tag.remaining);
      state++;
      memset(&x->asn1.u, 0, sizeof(x->asn1.u));
      break;

    case VNBEFORE_CONTENTS:
    case VNAFTER_CONTENTS:
      switch (x->asn1.u.timestamp.state) {
      case 0:
        x->asn1.u.timestamp.year = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 1:
        x->asn1.u.timestamp.year += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        break;
      case 2:
        x->asn1.u.timestamp.month = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 3:
        x->asn1.u.timestamp.month += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        break;
      case 4:
        x->asn1.u.timestamp.day = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 5:
        x->asn1.u.timestamp.day += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        break;
      case 6:
        x->asn1.u.timestamp.hour = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 7:
        x->asn1.u.timestamp.hour += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        break;
      case 8:
        x->asn1.u.timestamp.minute = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 9:
        x->asn1.u.timestamp.minute += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        break;
      case 10:
        x->asn1.u.timestamp.second = (px[i] - '0') * 10;
        x->asn1.u.timestamp.state++;
        break;
      case 11:
        x->asn1.u.timestamp.second += (px[i] - '0');
        x->asn1.u.timestamp.state++;
        {
          struct tm tm;
          time_t now;

          tm.tm_hour = x->asn1.u.timestamp.hour;
          tm.tm_isdst = 0;
          tm.tm_mday = x->asn1.u.timestamp.day;
          tm.tm_min = x->asn1.u.timestamp.minute;
          tm.tm_mon = x->asn1.u.timestamp.month - 1;
          tm.tm_sec = x->asn1.u.timestamp.second;
          tm.tm_wday = 0;
          tm.tm_yday = 0;
          tm.tm_year = 100 + x->asn1.u.timestamp.year;

          now = mktime(&tm);

          // tm = *localtime(&now);
          if (state == VNBEFORE_CONTENTS)
            x->prev = now;
          else {
            ; // printf("validity:%u-days\n", (now-x->prev)/(24*60*60));
          }
        }
        break;
      case 12:
        break;
      }
      break;

    case PADDING:
      /* [ASN1-CHILD-UNDERFLOW]
       * This state is reached when we've parsed everything inside an
       * ASN.1 field, yet there are still bytes left to parse. There
       * are TWO reasons why we reach this state.
       *  #1  there is a strict DER encoding problem, and we ought
       *      to flag the error
       *  #2  are parser is incomplete; we simply haven't added code
       *      for all fields yet, and therefore treat them as padding
       * We should flag the DER failure, but we can't, because the
       * existence of unparsed fields mean we'll falsely trigger DER
       * errors all the time.
       *
       * Note that due to the state-machine style parsing, we don't do
       * anything in this field. This problem naturally takes care of
       * itself.
       */
      break;

    case PUBKEY0_CONTENTS:
    case ENC_CONTENTS:
    case ERROR:
    default:
      ASN1_skip(&x->asn1, &i, length);
      break;
    }
  }

  /* Save the state variable and exit */
  if (x->asn1.state != ERROR)
    x->asn1.state = (unsigned int)state;
}

/****************************************************************************
 * This function must be called to set the initial state.
 * @param length
 *      The size of the certificate. This is parsed from the SSL/TLS field.
 *      We know that if we exceed this number of bytes, then an overflow has
 *      occurred.
 ****************************************************************************/
void x509_decode_init(struct CertDecode *x, size_t length) {
  memset(x, 0, sizeof(*x));
  ASN1_push(&x->asn1, STATE_ASN1_ERROR, length);
}
