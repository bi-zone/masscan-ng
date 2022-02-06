/*
        POP3 banner checker
*/
#include "proto-pop3.h"
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
static void pop3_parse(const struct Banner1 *banner1, void *banner1_private,
                       struct ProtocolState *pstate,
                       struct ResendPayload *resend_payload,
                       const unsigned char *px, size_t length,
                       struct BannerOutput *banout, struct SignOutput *signout,
                       struct KeyOutput **keyout,
                       struct InteractiveData *more) {

  size_t state = pstate->state;
  size_t i;
  UNUSEDPARM(banner1_private);
  UNUSEDPARM(banner1);
  UNUSEDPARM(signout);

  assert(pstate->parser_stream == &banner_pop3);

  for (i = 0; i < length; i++) {
    if (px[i] == '\r')
      continue;

    switch (state) {
    case 0:
    case 1:
    case 2:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if ("+OK"[state] != px[i]) {
        state = ERROR_STATE;
        tcp_close(more);
      } else
        state++;
      break;
    case 3:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '\n') {
        tcp_transmit(more, "CAPA\r\n", 6, 0);
        state++;
      }
      break;
    case 4:
    case 204:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '-')
        state = 100;
      else if (px[i] == '+')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 5:
    case 205:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == 'O')
        state++;
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 6:
    case 206:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == 'K')
        state += 2; /* oops, I had too many states here */
      else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 8:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '\n')
        state++;
      break;
    case 9:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '.')
        state++;
      else if (px[i] == '\n')
        continue;
      else
        state--;
      break;
    case 10:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '\n') {
        tcp_transmit(more, "STLS\r\n", 6, 0);
        state = 204;
      } else {
        state = 8;
      }
      break;
    case 208:
      banout_append_char(banout, PROTO_POP3, px[i]);
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
    case 100:
      banout_append_char(banout, PROTO_POP3, px[i]);
      if (px[i] == '\n') {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    default:
      i = length;
      break;
    }
  }
  pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *pop3_init(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return 0;
}

static void pop3_cleanup(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return;
}

/***************************************************************************
 ***************************************************************************/
static int pop3_selftest(void) { return 0; }

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_pop3 = {
    "pop3",        PROTO_POP3, false,        NULL, 0,          0,
    pop3_selftest, pop3_init,  pop3_cleanup, NULL, pop3_parse,
};
