/*
    SERVICE VERSIONING
*/
#include "versioning.h"
#include "masscan-app.h"
#include "massip-port.h"
#include "output.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "proto-preprocess.h"
#include "proto-ssl.h"
#include "proto-udp.h"
#include "smack.h"
#include "syn-cookie.h"
#include "util-cross.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/***************************************************************************
 ***************************************************************************/
static void
versioning_tcp_parse(const struct Banner1 *banner1, void *banner1_private,
                     struct ProtocolState *pstate,
                     struct ResendPayload *resend_payload,
                     const unsigned char *px, size_t length,
                     struct BannerOutput *banout, struct SignOutput *signout,
                     struct KeyOutput **keyout, struct InteractiveData *more) {

  UNUSEDPARM(banner1);
  UNUSEDPARM(banner1_private);
  UNUSEDPARM(keyout);
  UNUSEDPARM(pstate);
  UNUSEDPARM(resend_payload);
  UNUSEDPARM(signout);
  UNUSEDPARM(px);
  UNUSEDPARM(length);
  UNUSEDPARM(banout);
  UNUSEDPARM(more);
}

/***************************************************************************
 ***************************************************************************/
static void *versioning_init(struct Banner1 *b) { return b->http_fields; }

static void versioning_cleanup(struct Banner1 *b) {
  UNUSEDPARM(b);
  return;
}

/***************************************************************************
 ***************************************************************************/
#if 0
static unsigned
versioning_udp_parse(struct Output *out, time_t timestamp,
                    const unsigned char *px, unsigned length,
                    struct PreprocessedInfo *parsed,
                    uint64_t entropy
                    )
{
    
    return default_udp_parse(out, timestamp, px, length, parsed, entropy);
}
#endif

/****************************************************************************
 ****************************************************************************/
#if 0
static unsigned
versioning_udp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    return 0;
}
#endif

/***************************************************************************
 ***************************************************************************/
static int versioning_selftest(void) { return 0; }

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_versioning = {
    "versioning",
    PROTO_VERSIONING,
    false,
    "stats\r\n",
    7,
    0,
    versioning_selftest,
    versioning_init,
    versioning_cleanup,
    NULL,
    versioning_tcp_parse,
};
