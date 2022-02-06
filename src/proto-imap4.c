/*
 imap4 banner checker
 */
#include "proto-imap4.h"
#include "masscan-app.h"
#include "proto-banner1.h"
#include "proto-http-over-ssl.h"
#include "proto-interactive.h"
#include "proto-ssl.h"
#include "proto-tcp.h"
#include "util-cross.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

/***************************************************************************
 ***************************************************************************/
static void imap4_parse(const struct Banner1 *banner1, void *banner1_private,
                        struct ProtocolState *pstate,
                        struct ResendPayload *resend_payload,
                        const unsigned char *px, size_t length,
                        struct BannerOutput *banout, struct SignOutput *signout,
                        struct KeyOutput **keyout,
                        struct InteractiveData *more) {

  size_t state = pstate->state;
  size_t i;
  UNUSEDPARM(banner1_private);
  UNUSEDPARM(signout);

  assert(pstate->parser_stream == &banner_imap4);

  for (i = 0; i < length; i++) {
    if (px[i] == '\r')
      continue;

    switch (state) {
    case 0:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '*')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 1:
      if (px[i] == ' ') {
        banout_append_char(banout, PROTO_IMAP4, px[i]);
        continue;
      } else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      /* fall through */
    case 2:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == 'O')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 3:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == 'K')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 4:
      if (px[i] == ' ') {
        banout_append_char(banout, PROTO_IMAP4, px[i]);
        state++;
        break;
      } else if (px[i] != '\n') {
        banout_append_char(banout, PROTO_IMAP4, px[i]);
        /* no transition */
        break;
      } else {
        state++;
        /* fall through */
      }
    case 5:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '\n') {
        tcp_transmit(more, "a001 CAPABILITY\r\n", 17, 0);
        state = 100;
      }
      break;
    case 100:
    case 300:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '*')
        state += 100;
      else if (px[i] == 'a')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 101:
    case 301:
    case 102:
    case 302:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '0')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 103:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '1')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 303:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '2')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 104:
    case 304:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == ' ')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 105:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '\n') {
        tcp_transmit(more, "a002 STARTTLS\r\n", 15, 0);
        state = 300;
      }
      break;

    case 200:
    case 400:
      banout_append_char(banout, PROTO_IMAP4, px[i]);
      if (px[i] == '\n')
        state -= 100;
      break;

    case 305:
      if (px[i] == '\n') {
        /* change the state here to SSL */
        switch_application_proto(banner1, pstate, resend_payload, banout,
                                 keyout, PROTO_SSL3,
                                 get_ssl_parser_stream(banner1));
        application_receive_hello(banner1, pstate, resend_payload, banout,
                                  keyout, more);
        return;
      }
      break;

    case ERROR_STATE:
    default:
      i = length;
      break;
    }
  }
  pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *imap4_init(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return 0;
}

static void imap4_cleanup(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return;
}

/***************************************************************************
 ***************************************************************************/
static int imap4_selftest(void) { return 0; }

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_imap4 = {
    "imap4",        PROTO_IMAP4, false,         NULL, 0,           0,
    imap4_selftest, imap4_init,  imap4_cleanup, NULL, imap4_parse,
};
