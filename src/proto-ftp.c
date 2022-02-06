#include "proto-ftp.h"
#include "masscan-app.h"
#include "proto-banner1.h"
#include "proto-http-over-ssl.h"
#include "proto-interactive.h"
#include "proto-tcp.h"
#include "util-cross.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

/***************************************************************************
 ***************************************************************************/
static void ftp_parse(const struct Banner1 *banner1, void *banner1_private,
                      struct ProtocolState *pstate,
                      struct ResendPayload *resend_payload,
                      const unsigned char *px, size_t length,
                      struct BannerOutput *banout, struct SignOutput *signout,
                      struct KeyOutput **keyout, struct InteractiveData *more) {

  size_t state = pstate->state;
  size_t i;
  struct FTPSTUFF *ftp = &pstate->sub.ftp;
  UNUSEDPARM(signout);
  UNUSEDPARM(banner1_private);
  UNUSEDPARM(banner1);

  assert(pstate->parser_stream == &banner_ftp);

  for (i = 0; i < length; i++) {

    switch (state) {
    case 0:
    case 100:
      ftp->code = 0;
      state++;
      /* fall through */
    case 1:
    case 2:
    case 3:
    case 101:
    case 102:
    case 103:
      if (!isdigit(px[i] & 0xFF)) {
        state = ERROR_STATE;
        tcp_close(more);
      } else {
        ftp->code *= 10;
        ftp->code += (px[i] - '0');
        state++;
        banout_append_char(banout, PROTO_FTP, px[i]);
      }
      break;
    case 4:
    case 104:
      if (px[i] == ' ') {
        ftp->is_last = 1;
        state++;
        banout_append_char(banout, PROTO_FTP, px[i]);
      } else if (px[i] == '-') {
        ftp->is_last = 0;
        state++;
        banout_append_char(banout, PROTO_FTP, px[i]);
      } else {
        state = ERROR_STATE;
        tcp_close(more);
      }
      break;
    case 5:
      if (px[i] == '\r')
        continue;
      else if (px[i] == '\n') {
        if (ftp->is_last) {
          tcp_transmit(more, "AUTH TLS\r\n", 10, 0);
          state = 100;
          banout_append_char(banout, PROTO_FTP, px[i]);
        } else {
          banout_append_char(banout, PROTO_FTP, px[i]);
          state = 0;
        }
      } else if (px[i] == '\0' || !isprint(px[i])) {
        state = ERROR_STATE;
        tcp_close(more);
        continue;
      } else {
        banout_append_char(banout, PROTO_FTP, px[i]);
      }
      break;
    case 105:
      if (px[i] == '\r')
        continue;
      else if (px[i] == '\n') {

        if (ftp->code == 234) {

          /* change the state here to SSL */
          switch_application_proto(banner1, pstate, resend_payload, banout,
                                   keyout, PROTO_SSL3,
                                   get_ssl_parser_stream(banner1));
          application_receive_hello(banner1, pstate, resend_payload, banout,
                                    keyout, more);
          return;

        } else {
          state = ERROR_STATE;
          tcp_close(more);
        }
      } else if (px[i] == '\0' || !isprint(px[i])) {
        state = ERROR_STATE;
        tcp_close(more);
        continue;
      } else {
        banout_append_char(banout, PROTO_FTP, px[i]);
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
static void *ftp_init(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return NULL;
}

static void ftp_cleanup(struct Banner1 *banner1) {
  UNUSEDPARM(banner1);
  return;
}

/***************************************************************************
 ***************************************************************************/
static int ftp_selftest(void) { return 0; }

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_ftp = {
    "ftp",        PROTO_FTP, false,       NULL, 0,         0,
    ftp_selftest, ftp_init,  ftp_cleanup, NULL, ftp_parse,
};
