#ifndef PROTO_X509_H
#define PROTO_X509_H
#include <stdint.h>
#include <time.h>

#include "proto-asn1.h"

struct BannerOutput;

/****************************************************************************
 * This stores the "state" of the X.509 certificate parser
 ****************************************************************************/
struct CertDecode {

  struct ASN1Decode asn1;

  unsigned is_capture_subject : 1;
  unsigned is_capture_issuer : 1;

  /** Number of certificates we've processed */
  unsigned char count;

  /** ??? */
  time_t prev;

  /** This parser was originally written just to grab the "subect name"
   * of a certificate, i.e. "*.google.com" for Google's certificates.
   * However, there are many different types of subject names. Each
   * subject name comes in two parts, the first part being an OID
   * saying the type of subject, then the subject itself. We need to stash
   * the result of parsing the OID somewhere before parsing the subject
   */
  struct {
    unsigned type;
  } subject;
};

/* Called before parsing the first fragment of an X.509 certificate */
void x509_decode_init(struct CertDecode *x, size_t length);

/**  Called to decode the next fragment of an X.509 certificate.
 * Must call x509_decode_init() first. */
void x509_decode(struct CertDecode *x, const unsigned char *px, size_t length,
                 struct BannerOutput *banout);

/** Called at program startup to initialize internal parsing structures
 * for certificates. Once called, it creates static read-only thread-safe
 * structures */
void x509_init(void);

#endif
