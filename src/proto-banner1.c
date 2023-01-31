/*
     state machine for receiving banners
*/
#include "proto-banner1.h"
#include "logger.h"
#include "masscan-app.h"
#include "proto-ftp.h"
#include "proto-http-over-ssl.h"
#include "proto-http.h"
#include "proto-imap4.h"
#include "proto-interactive.h"
#include "proto-keyout.h"
#include "proto-memcached.h"
#include "proto-pop3.h"
#include "proto-preprocess.h"
#include "proto-signout.h"
#include "proto-smb.h"
#include "proto-smtp.h"
#include "proto-ssh.h"
#include "proto-ssl.h"
#include "proto-statout.h"
#include "proto-tcp-rdp.h"
#include "proto-tcp-telnet.h"
#include "proto-tcp.h"
#include "proto-vnc.h"
#include "rawsock-pcapfile.h"
#include "scripting.h"
#include "smack.h"
#include "util-malloc.h"
#include "versioning.h"

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct Patterns patterns[] = {
    {"\x00\x00"
     "**"
     "\xff"
     "SMB",
     8, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN | SMACK_WILDCARDS, 0},
    {"\x00\x00"
     "**"
     "\xfe"
     "SMB",
     8, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN | SMACK_WILDCARDS, 0},

    {"\x82\x00\x00\x00", 4, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Positive Session Response */

    {"\x83\x00\x00\x01\x80", 5, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Not listening on called name */
    {"\x83\x00\x00\x01\x81", 5, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Not listening for calling name */
    {"\x83\x00\x00\x01\x82", 5, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Called name not present */
    {"\x83\x00\x00\x01\x83", 5, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Called name present, but insufficient resources */
    {"\x83\x00\x00\x01\x8f", 5, NOT_HAVE_OFFSET, PROTO_SMB, SMACK_ANCHOR_BEGIN,
     0}, /* Unspecified error */

    /* ...the remainder can be in any order */
    {"SSH-1.", 6, NOT_HAVE_OFFSET, PROTO_SSH1, SMACK_ANCHOR_BEGIN, 0},
    {"SSH-2.", 6, NOT_HAVE_OFFSET, PROTO_SSH2, SMACK_ANCHOR_BEGIN, 0},
    {"HTTP/1.", 7, NOT_HAVE_OFFSET, PROTO_HTTP, SMACK_ANCHOR_BEGIN, 0},
    {"220-", 4, NOT_HAVE_OFFSET, PROTO_FTP, SMACK_ANCHOR_BEGIN, 0},
    {"220 ", 4, NOT_HAVE_OFFSET, PROTO_FTP, SMACK_ANCHOR_BEGIN, 1},
    {"+OK ", 4, NOT_HAVE_OFFSET, PROTO_POP3, SMACK_ANCHOR_BEGIN, 0},
    {"* OK ", 5, NOT_HAVE_OFFSET, PROTO_IMAP4, SMACK_ANCHOR_BEGIN, 0},
    {"521 ", 4, NOT_HAVE_OFFSET, PROTO_SMTP, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x00", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x01", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x02", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x03", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x00", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x01", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x02", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x03", 3, NOT_HAVE_OFFSET, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"RFB 000.000\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     1}, /* UltraVNC repeater mode */
    {"RFB 003.003\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     3}, /* default version for everything */
    {"RFB 003.005\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     3}, /* broken, same as 003.003 */
    {"RFB 003.006\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     3}, /* broken, same as 003.003 */
    {"RFB 003.007\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     7},
    {"RFB 003.008\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8},
    {"RFB 003.889\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8}, /* Apple's remote desktop, 003.007 */
    {"RFB 003.009\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8},
    {"RFB 004.000\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8}, /* Intel AMT KVM */
    {"RFB 004.001\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8}, /* RealVNC 4.6 */
    {"RFB 004.002\n", 12, NOT_HAVE_OFFSET, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN,
     8},
    {"STAT pid ", 9, NOT_HAVE_OFFSET, PROTO_MEMCACHED, SMACK_ANCHOR_BEGIN,
     0}, /* memcached stat response */

    {"\xff\xfb\x01\xff\xf0", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfb", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfc", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfe", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0a\x0d", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0d\x0a", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0d\x0d", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0a\x0a", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb%\x25xff\xfb", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x26\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x18\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x20\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x23\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x27\xff\xfd", 5, NOT_HAVE_OFFSET, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x1b[", 5, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN,
     0},
    {"\xff\xfb\x01Input", 8, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN,
     0},
    {"\xff\xfb\x01   ", 6, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN,
     0},
    {"\xff\xfb\x01login", 8, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN,
     0},
    {"login:", 6, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"password:", 9, NOT_HAVE_OFFSET, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},

    {"\x03\x00\x00\x13\x0e\xd0\xbe\xef\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00"
     "\x00",
     12, NOT_HAVE_OFFSET, PROTO_RDP, SMACK_ANCHOR_BEGIN, 0},
    {"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00"
     "\x00",
     12, NOT_HAVE_OFFSET, PROTO_RDP, SMACK_ANCHOR_BEGIN, 0},
    /* custom */
    {"\x4d\x5a\xe8\x00", 4, PROTO_MSF, 0, 0,
     4}, /* MZ pattern, size: 4, PROTO, offset: 4 */
    {NULL, 0, 0, 0, 0, 0}};

/***************************************************************************
 ***************************************************************************/
enum ApplicationProtocol banner1_detect_proto(const struct Banner1 *banner1,
                                              struct ProtocolState *tcb_state,
                                              const unsigned char *px,
                                              size_t length) {

  if (tcb_state->app_proto == PROTO_NONE ||
      tcb_state->app_proto == PROTO_HEUR) {
    size_t x;
    enum ApplicationProtocol proto;
    size_t offset = 0;

    while (true) {
      x = smack_search_next(banner1->smack, &tcb_state->state, px, &offset,
                            length);
      if (x != SMACK_NOT_FOUND &&
          patterns[x].pattern_offset != NOT_HAVE_OFFSET) {
        size_t abs_offfset =
            tcb_state->detect_offset + offset - patterns[x].pattern_length;
        if (abs_offfset != patterns[x].pattern_offset) {
          continue;
        }
      }
      break;
    }

    if (x != SMACK_NOT_FOUND) {
      proto = patterns[x].id;
    } else {
      proto = PROTO_NONE;
    }

    if (proto != PROTO_NONE &&
        !(proto == PROTO_SSL3 && !tcb_state->is_sent_sslhello)) {
      /* Kludge: patterns look confusing, so add port info to the
       * pattern */
      switch (proto) {
      case PROTO_FTP:
        if (patterns[x].extra == 1 &&
            (tcb_state->port == 25 || tcb_state->port == 587)) {
          proto = PROTO_SMTP;
        }
        break;
      case PROTO_VNC_RFB:
        tcb_state->sub.vnc.version = (unsigned char)patterns[x].extra;
        break;
      default:
        break;
      }
    } else {
      proto = PROTO_NONE;
    }
    tcb_state->detect_offset += length;
    return proto;
  }

  return tcb_state->app_proto;
}

const struct ProtocolParserStream *
banner1_get_parse_stream_by_app_proto(const struct Banner1 *banner1,
                                      enum ApplicationProtocol app_proto) {

  switch (app_proto) {
  case PROTO_FTP:
    return &banner_ftp;
  case PROTO_SMTP:
    return &banner_smtp;
  case PROTO_TELNET:
    return &banner_telnet;
  case PROTO_RDP:
    return &banner_rdp;
  case PROTO_POP3:
    return &banner_pop3;
  case PROTO_IMAP4:
    return &banner_imap4;
  case PROTO_SSH1:
  case PROTO_SSH2:
    /* generic text-based parser
     * TODO: in future, need to split these into separate protocols,
     * especially when binary parsing is added to SSH */
    return &banner_ssh;
  case PROTO_HTTPS:
  case PROTO_HTTP:
    return &banner_http;
  case PROTO_SSL3:
    return get_ssl_parser_stream(banner1);
  case PROTO_SMB:
    return &banner_smb1;
  case PROTO_VNC_RFB:
    return &banner_vnc;
  case PROTO_MEMCACHED:
    return &banner_memcached;
  case PROTO_SCRIPTING:
    return &banner_scripting;
  case PROTO_VERSIONING:
    return &banner_versioning;
  case PROTO_MSF:
    return NULL;
  default:
    LOG(LEVEL_WARNING, "banner1: internal error\n");
    break;
  }
  return NULL;
}

/***************************************************************************
 * Create the --banners systems
 ***************************************************************************/
struct Banner1 *banner1_create(void) {
  struct Banner1 *b;
  size_t i;

  b = CALLOC(1, sizeof(*b));

  /* This creates a pattern-matching blob for heuristically determining
   * a protocol that runs on wrong ports, such as how FTP servers
   * often respond with "220 " or VNC servers respond with "RFB". */
  b->smack = smack_create("banner1", SMACK_CASE_INSENSITIVE);
  for (i = 0; patterns[i].pattern; i++) {
    smack_add_pattern(b->smack, patterns[i].pattern, patterns[i].pattern_length,
                      i, patterns[i].is_anchored);
  }
  smack_compile(b->smack);

  return b;
}

void banner1_init(struct Banner1 *b) {
  b->payloads.tcp[80] = &banner_http;
  b->payloads.tcp[8080] = &banner_http;
  b->payloads.tcp[139] = &banner_smb0;
  b->payloads.tcp[445] = &banner_smb1;
  b->payloads.tcp[443] = get_ssl_parser_stream(b); /* HTTP/s */
  b->payloads.tcp[465] = get_ssl_parser_stream(b); /* SMTP/s */
  b->payloads.tcp[990] = get_ssl_parser_stream(b); /* FTP/s */
  b->payloads.tcp[991] = get_ssl_parser_stream(b);
  b->payloads.tcp[992] = get_ssl_parser_stream(b); /* Telnet/s */
  b->payloads.tcp[993] = get_ssl_parser_stream(b); /* IMAP4/s */
  b->payloads.tcp[994] = get_ssl_parser_stream(b);
  b->payloads.tcp[995] = get_ssl_parser_stream(b);  /* POP3/s */
  b->payloads.tcp[2083] = get_ssl_parser_stream(b); /* cPanel - SSL */
  b->payloads.tcp[2087] = get_ssl_parser_stream(b); /* WHM - SSL */
  b->payloads.tcp[2096] = get_ssl_parser_stream(b); /* cPanel webmail - SSL */
  b->payloads.tcp[8443] =
      get_ssl_parser_stream(b); /* Plesk Control Panel - SSL */
  b->payloads.tcp[9050] = get_ssl_parser_stream(b); /* Tor */
  b->payloads.tcp[8140] = get_ssl_parser_stream(b); /* puppet */
  b->payloads.tcp[11211] = &banner_memcached;
  b->payloads.tcp[23] = &banner_telnet;
  b->payloads.tcp[3389] = &banner_rdp;

  /* This goes down the list of all the TCP protocol handlers and initializes
   * them. */
  banner_ftp.init(b);
  banner_http.init(b);
  banner_imap4.init(b);
  banner_memcached.init(b);
  banner_pop3.init(b);
  banner_smtp.init(b);
  banner_ssh.init(b);
  banner_ssl.init(b);
  banner_http_over_ssl.init(b);
  banner_smb0.init(b);
  banner_smb1.init(b);
  banner_telnet.init(b);
  banner_rdp.init(b);
  banner_vnc.init(b);

  /* scripting/versioning come after the rest */
  banner_scripting.init(b);
  banner_versioning.init(b);

  return;
}

/***************************************************************************
 ***************************************************************************/
void banner1_destroy(struct Banner1 *b) {
  size_t i;

  if (b == NULL) {
    return;
  }

  banner_versioning.cleanup(b);
  banner_scripting.cleanup(b);

  banner_ftp.cleanup(b);
  banner_http.cleanup(b);
  banner_imap4.cleanup(b);
  banner_memcached.cleanup(b);
  banner_pop3.cleanup(b);
  banner_smtp.cleanup(b);
  banner_ssh.cleanup(b);
  banner_ssl.cleanup(b);
  banner_http_over_ssl.cleanup(b);
  banner_smb0.cleanup(b);
  banner_smb1.cleanup(b);
  banner_telnet.cleanup(b);
  banner_rdp.cleanup(b);
  banner_vnc.cleanup(b);

  for (i = 0; i < COUNT_TCP_PORTS; i++) {
    if (b->payloads.tcp[i] && b->payloads.tcp[i]->is_dynamic) {
      free((void *)b->payloads.tcp[i]->hello);
      free(b->payloads.tcp[i]);
    }
  }

  if (b->smack) {
    smack_destroy(b->smack);
  }
  if (b->http_fields) {
    smack_destroy(b->http_fields);
  }
  free(b);
}

/***************************************************************************
 * Test the banner1 detection system by throwing random frames at it
 ***************************************************************************/
int banner1_test(const char *filename) {

  struct PcapFile *cap;
  unsigned link_type;

  cap = pcapfile_openread(filename);
  if (cap == NULL) {
    LOG(LEVEL_ERROR, "%s: can't open capture file\n", filename);
    return 1;
  }

  link_type = pcapfile_datalink(cap);
  for (;;) {
    int packets_read;
    unsigned secs;
    unsigned usecs;
    unsigned origlength;
    unsigned length;
    unsigned char px[65536];
    struct PreprocessedInfo parsed;
    unsigned x;

    packets_read =
        pcapfile_readframe(cap /* capture dump file */, &secs, &usecs,
                           &origlength, &length, px, sizeof(px));
    if (packets_read == 0)
      break;
    x = preprocess_frame(px, (size_t)length, link_type, &parsed);
    if (x == 0)
      continue;
  }

  pcapfile_close(cap);
  return 0;
}

/***************************************************************************
 ***************************************************************************/
int banner1_selftest() {
  size_t i;
  struct Banner1 *b;
  struct ProtocolState tcb_state[1];
  struct ResendPayload resend_payload;
  const unsigned char *px;
  size_t length;
  struct BannerOutput banout[1];
  struct SignOutput signout[1];
  struct KeyOutput *keyout = NULL;

  static const char *http_header =
      "HTTP/1.0 302 Redirect\r\n"
      "Date: Tue, 03 Sep 2013 06:50:01 GMT\r\n"
      "Connection: close\r\n"
      "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f "
      "])\r\n"
      "Server: YTS/1.20.13\r\n"
      "Cache-Control: no-store\r\n"
      "Content-Type: text/html\r\n"
      "Content-Language: en\r\n"
      "Location: http://failsafe.fp.yahoo.com/404.html\r\n"
      "Content-Length: 227\r\n"
      "\r\n<title>hello</title>\n";
  px = (const unsigned char *)http_header;
  length = strlen(http_header);

  /* First, test the "banout" subsystem */
  if (banout_selftest() != 0) {
    LOG(LEVEL_ERROR, "banout: failed\n");
    return 1;
  }

  if (statout_selftest() != 0) {
    LOG(LEVEL_ERROR, "statout: failed\n");
    return 1;
  }

  if (signout_selftest() != 0) {
    LOG(LEVEL_ERROR, "signout: failed\n");
    return 1;
  }

  if (keyout_selftest() != 0) {
    LOG(LEVEL_ERROR, "keyout: failed\n");
    return 1;
  }

  /* Test one character at a time */
  b = banner1_create();
  banner1_init(b);
  banout_init(banout);
  signout_init(signout);
  keyout_init(&keyout);

  memset(tcb_state, 0, sizeof(tcb_state[0]));

  for (i = 0; i < length; i++) {
    struct InteractiveData more = {0};
    application_receive_next(b, tcb_state, tcb_state, &resend_payload, px + i,
                             1, banout, signout, &keyout, &more);
    free_interactive_data(&more);
  }

  {
    const char *s = (const char *)banout_string(banout, PROTO_HTTP);
    if (s == NULL ||
        memcmp(s, "HTTP/1.0 302 ", sizeof("HTTP/1.0 302 ") - 1) != 0) {
      size_t s_length = sizeof("(null)");
      if (s != NULL) {
        s_length = banout_string_length(banout, PROTO_HTTP);
      }
      LOG(LEVEL_ERROR, "banner1: test failed: '%.*s' on LINE %d\n",
          (int)s_length, s == NULL ? "(null)" : s, __LINE__);
      keyout_release(&keyout);
      signout_release(signout);
      banout_release(banout);
      banner1_destroy(b);
      return 1;
    }
  }

  keyout_release(&keyout);
  signout_release(signout);
  banout_release(banout);
  banner1_destroy(b);

  /* Test whole buffer */
  b = banner1_create();
  banner1_init(b);
  banout_init(banout);
  signout_init(signout);
  keyout_init(&keyout);
  memset(tcb_state, 0, sizeof(tcb_state[0]));
  application_receive_next(b, tcb_state, tcb_state, &resend_payload, px, length,
                           banout, signout, &keyout, NULL);
  keyout_release(&keyout);
  signout_release(signout);
  banout_release(banout);
  banner1_destroy(b);
  /*if (memcmp(banner, "Via:HTTP/1.1", 11) != 0) {
      printf("banner1: test failed\n");
      return 1;
  }*/

  {
    int x = 0;

    x = banner_http_over_ssl.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "HTTP_OVER_SSL banner: selftest failed\n");
      return 1;
    }

    x = banner_ssl.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "SSL banner: selftest failed\n");
      return 1;
    }

    x = banner_smb1.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "SMB banner: selftest failed\n");
      return 1;
    }

    x = banner_http.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "HTTP banner: selftest failed\n");
      return 1;
    }

    x = banner_telnet.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "Telnet banner: selftest failed\n");
      return 1;
    }

    x = banner_rdp.selftest();
    if (x) {
      LOG(LEVEL_ERROR, "RDP banner: selftest failed\n");
      return 1;
    }

    return x;
  }
}
