/*
    TCP connection table
*/
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <time.h>

#include "crypto-base64.h"
#include "event-timeout.h" /* for tracking future events */
#include "logger.h"
#include "main-globals.h"
#include "output.h"
#include "pixie-timer.h"
#include "proto-banner1.h"
#include "proto-http-over-ssl.h"
#include "proto-http.h"
#include "proto-interactive.h"
#include "proto-keyout.h"
#include "proto-smb.h"
#include "proto-ssl.h"
#include "proto-tcp.h"
#include "rawsock.h"
#include "scripting.h"
#include "stack-queue.h"
#include "string_s.h"
#include "syn-cookie.h"
#include "templ-pkt.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "versioning.h"

struct TCP_ConnectionTable {
  struct TCP_Control_Block **entries;
  struct TCP_Control_Block *freed_list;
  size_t count;
  size_t mask;
  time_t timeout_connection;
  time_t timeout_hello;

  uint64_t active_count;
  uint64_t entropy;

  struct Timeouts *timeouts;
  struct TemplatePacket *pkt_template;
  struct stack_t *stack;

  struct Banner1 *banner1;
  OUTPUT_REPORT_BANNER report_banner;
  OUTPUT_REPORT_STATUS report_status;
  OUTPUT_REPORT_SIGN report_sign;
  OUTPUT_SSL_KEY ssl_key;
  struct Output *out;

  struct ScriptingVM *scripting_vm;
};

enum {
  STATE_SYN_SENT,
  // STATE_SYN_RECEIVED,
  STATE_ESTABLISHED_SEND, /* our own special state, can only send */
  STATE_ESTABLISHED_RECV, /* our own special state, can only receive */
  // STATE_CLOSE_WATI,
  STATE_LAST_ACK,
  STATE_FIN_WAIT1,
  STATE_FIN_WAIT2,
  STATE_CLOSING,
  STATE_TIME_WAIT,
};

/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs,
                     unsigned usecs) {

  uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

  for (;;) {
    struct TCP_Control_Block *tcb;

    /* Get the next event that is older than the current time */
    tcb = (struct TCP_Control_Block *)timeouts_remove(tcpcon->timeouts,
                                                      timestamp);

    /* If everything up to the current time has already been processed,
     * then exit this loop */
    if (tcb == NULL)
      break;

    /* Process this timeout */
    stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_TIMEOUT, 0, 0, secs, usecs,
                       tcb->seqno_them);

    /* If the TCB hasn't been destroyed, then we need to make sure
     * there is a timeout associated with it. KLUDGE: here is the problem:
     * there must ALWAYS be a 'timeout' associated with a TCB, otherwise,
     * we'll lose track of it and leak memory. In theory, this should be
     * automatically handled elsewhere, but I have bugs, and it's not,
     * so I put some code here as a catch-all: if the TCB hasn't been
     * deleted, but hasn't been inserted back into the timeout system,
     * then insert it here. */
    if (tcb->timeout->prev == NULL && tcb->is_active) {
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV((uint64_t)secs + 2, usecs));
    }
  }
}

/***************************************************************************
 ***************************************************************************/
static int name_equals(const char *lhs, const char *rhs) {
  for (;;) {
    while (*lhs == '-' || *lhs == '.' || *lhs == '_')
      lhs++;
    while (*rhs == '-' || *rhs == '.' || *rhs == '_')
      rhs++;
    if (*lhs == '\0' && *rhs == '[')
      return 1; /*arrays*/
    if (*rhs == '\0' && *lhs == '[')
      return 1; /*arrays*/
    if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
      return 0;
    if (*lhs == '\0')
      return 1;
    lhs++;
    rhs++;
  }
}

/***************************************************************************
 * When setting parameters, this will parse integers from the config
 * parameter strings.
 ***************************************************************************/
static uint64_t parseInt(const void *vstr, size_t length) {
  const char *str = (const char *)vstr;
  uint64_t result = 0;
  size_t i;

  for (i = 0; i < length; i++) {
    result = result * 10 + ((uint64_t)str[i] - '0');
  }
  return result;
}

/***************************************************************************
 * Called at startup, when processing command-line options, to set
 * an HTTP field.
 ***************************************************************************/
void tcpcon_set_http_header(struct TCP_ConnectionTable *tcpcon,
                            const char *name, size_t value_length,
                            const void *value, enum http_field_t what) {
  UNUSEDPARM(tcpcon);
  banner_http.hello_length = http_change_field(
      (unsigned char **)&banner_http.hello, banner_http.hello_length, name,
      (const unsigned char *)value, value_length, what);
}

/***************************************************************************
 * Called at startup, when processing command-line options, to set
 * parameters specific to TCP processing.
 ***************************************************************************/
void tcpcon_set_parameter(struct TCP_ConnectionTable *tcpcon, const char *name,
                          size_t value_length, const void *value) {

  struct Banner1 *banner1 = tcpcon->banner1;

  if (name_equals(name, "http-payload")) {
    char lenstr[64];
    sprintf_s(lenstr, sizeof(lenstr), "%" PRIuPTR, value_length);

    banner_http.hello_length = http_change_requestline(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        (const unsigned char *)value, value_length, http_request_line_payload);

    banner_http.hello_length = http_change_field(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        "Content-Length:", (const unsigned char *)lenstr, strlen(lenstr),
        http_field_replace);
    return;
  }

  /* You can reset your user-agent here. Whenever I do a scan, I always
   * reset my user-agent. That's now you know it's not me scanning
   * you on the open Internet -- I would never use the default user-agent
   * string built into masscan */
  if (name_equals(name, "http-user-agent")) {
    banner_http.hello_length = http_change_field(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        "User-Agent:", (const unsigned char *)value, value_length,
        http_field_replace);
    return;
  }

  if (name_equals(name, "http-host")) {
    banner_http.hello_length = http_change_field(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        "Host:", (const unsigned char *)value, value_length,
        http_field_replace);
    return;
  }

  /* Changes the URL */
  if (name_equals(name, "http-method")) {
    banner_http.hello_length = http_change_requestline(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        (const unsigned char *)value, value_length, http_request_line_method);
    return;
  }
  if (name_equals(name, "http-url")) {
    banner_http.hello_length = http_change_requestline(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        (const unsigned char *)value, value_length, http_request_line_url);
    return;
  }
  if (name_equals(name, "http-version")) {
    banner_http.hello_length = http_change_requestline(
        (unsigned char **)&banner_http.hello, banner_http.hello_length,
        (const unsigned char *)value, value_length, http_request_line_version);
    return;
  }

  if (name_equals(name, "timeout") || name_equals(name, "connection-timeout")) {
    uint64_t n = parseInt(value, value_length);
    tcpcon->timeout_connection = (time_t)n;
    LOG(LEVEL_INFO, "TCP connection-timeout = %u\n",
        tcpcon->timeout_connection);
    return;
  }
  if (name_equals(name, "hello-timeout")) {
    uint64_t n = parseInt(value, value_length);
    tcpcon->timeout_hello = (time_t)n;
    LOG(LEVEL_INFO, "TCP hello-timeout = \"%.*s\"\n", (int)value_length,
        (const char *)value);
    LOG(LEVEL_INFO, "TCP hello-timeout = %" PRIu64 "\n", tcpcon->timeout_hello);
    return;
  }
  /* Force SSL processing on all ports */
  if (name_equals(name, "hello") && name_equals(value, "ssl")) {
    size_t i;
    LOG(LEVEL_DEBUG, "HELLO: setting SSL hello message\n");
    for (i = 0; i < 65535; i++) {
      banner1->payloads.tcp[i] = get_ssl_parser_stream(banner1);
    }
    return;
  }
  /* Force HTTP processing on all ports */
  if (name_equals(name, "hello") && name_equals(value, "http")) {
    size_t i;
    LOG(LEVEL_DEBUG, "HELLO: setting HTTP hello message\n");
    for (i = 0; i < 65535; i++) {
      banner1->payloads.tcp[i] = &banner_http;
    }
    return;
  }
  /* Downgrade SMB hello from v1/v2 to use only v1 */
  if (name_equals(name, "hello") && name_equals(value, "smbv1")) {
    smb_set_hello_v1(&banner_smb1);
    return;
  }
  /* 2014-04-08: scan for Neel Mehta's "heartbleed" bug */
  if (name_equals(name, "heartbleed")) {
    size_t i;
    if (tcpcon->banner1->is_ssl_dynamic) {
      LOG(LEVEL_ERROR, "heartbleed not implement with ssl_dynamic\n");
      exit(1);
    }
    /* Change the hello message to including negotiating the use of
     * the "heartbeat" extension */
    banner_ssl.hello = ssl_hello(ssl_hello_heartbeat_template);
    banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
    tcpcon->banner1->is_heartbleed = 1;

    for (i = 0; i < 65535; i++) {
      banner1->payloads.tcp[i] = &banner_ssl;
    }
    return;
  }
  if (name_equals(name, "ticketbleed")) {
    size_t i;
    if (tcpcon->banner1->is_ssl_dynamic) {
      LOG(LEVEL_ERROR, "ticketbleed not implement with ssl_dynamic\n");
      exit(1);
    }
    /* Change the hello message to including negotiating the use of
     * the "heartbeat" extension */
    banner_ssl.hello = ssl_hello(ssl_hello_ticketbleed_template);
    banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
    tcpcon->banner1->is_ticketbleed = 1;

    for (i = 0; i < 65535; i++) {
      banner1->payloads.tcp[i] = &banner_ssl;
    }
    return;
  }

  /* 2014-10-16: scan for SSLv3 servers (POODLE) */
  if (name_equals(name, "poodle") || name_equals(name, "sslv3")) {
    size_t i;
    void *px;

    if (tcpcon->banner1->is_ssl_dynamic) {
      LOG(LEVEL_ERROR, "poodle not implement with ssl_dynamic\n");
      exit(1);
    }

    /* Change the hello message to including negotiating the use of
     * the "heartbeat" extension */
    px = ssl_hello(ssl_hello_sslv3_template);
    banner_ssl.hello = ssl_add_cipherspec(px, 0x5600, 1);
    banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
    tcpcon->banner1->is_poodle_sslv3 = 1;

    for (i = 0; i < 65535; i++) {
      banner1->payloads.tcp[i] = &banner_ssl;
    }
    return;
  }
  /* You can reconfigure the "hello" message to be anything
   * you want. */
  if (name_equals(name, "hello-string")) {
    struct ProtocolParserStream *x_old;
    struct ProtocolParserStream *x_new;
    const char *p = strchr(name, '[');
    unsigned port;

    if (p == NULL) {
      LOG(LEVEL_ERROR, "tcpcon: parameter: expected array []: %s\n", name);
      exit(1);
    }
    port = (unsigned)strtoul(p + 1, 0, 0);
    x_old = banner1->payloads.tcp[port];
    x_new = CALLOC(1, sizeof(*x_old));
    if (x_old == NULL) {
      x_new->name = "(allocated)";
    } else {
      assert(x_old->is_dynamic == false);
      memcpy(x_new, x_old, sizeof(*x_old));
    }
    x_new->is_dynamic = true;

    x_new->hello = MALLOC(value_length);
    x_new->hello_length =
        base64_decode((char *)x_new->hello, value_length, value, value_length);
    x_new->transmit_hello = NULL;

    banner1->payloads.tcp[port] = x_new;
    return;
  }
}

/***************************************************************************
 ***************************************************************************/
void tcpcon_set_banner_flags(struct TCP_ConnectionTable *tcpcon,
                             bool is_capture_cert, bool is_capture_servername,
                             bool is_ssl_dynamic, bool is_capture_key,
                             bool is_capture_html, bool is_capture_heartbleed,
                             bool is_capture_ticketbleed,
                             bool is_dynamic_set_host) {
  tcpcon->banner1->is_capture_cert = is_capture_cert;
  tcpcon->banner1->is_ssl_dynamic = is_ssl_dynamic;
  tcpcon->banner1->is_capture_key = is_capture_key;
  tcpcon->banner1->is_capture_servername = is_capture_servername;
  tcpcon->banner1->is_capture_html = is_capture_html;
  tcpcon->banner1->is_capture_heartbleed = is_capture_heartbleed;
  tcpcon->banner1->is_capture_ticketbleed = is_capture_ticketbleed;
  tcpcon->banner1->is_dynamic_set_host = is_dynamic_set_host;
}

void tcpcon_set_regexp(struct TCP_ConnectionTable *tcpcon, pcre *re,
                       pcre_extra *re_extra, unsigned is_regex_only_banners) {
  tcpcon->banner1->regex = re;
  tcpcon->banner1->regex_extra = re_extra;
  tcpcon->banner1->is_regex_only_banners = is_regex_only_banners;
}

/***************************************************************************
 ***************************************************************************/
void scripting_init_tcp(struct TCP_ConnectionTable *tcpcon,
                        struct lua_State *L) {
  tcpcon->banner1->L = L;
  banner_scripting.init(tcpcon->banner1);
}

void tcpcon_init_banner1(struct TCP_ConnectionTable *tcpcon) {
  banner1_init(tcpcon->banner1);
}

/***************************************************************************
 * Called at startup, by a receive thread, to create a TCP connection
 * table.
 ***************************************************************************/
struct TCP_ConnectionTable *tcpcon_create_table(
    size_t entry_count, struct stack_t *stack,
    struct TemplatePacket *pkt_template, OUTPUT_REPORT_SIGN report_sign,
    OUTPUT_REPORT_STATUS report_status, OUTPUT_REPORT_BANNER report_banner,
    OUTPUT_SSL_KEY ssl_key, struct Output *out, time_t connection_timeout,
    uint64_t entropy) {

  struct TCP_ConnectionTable *tcpcon;
  size_t size_entries;

  tcpcon = CALLOC(1, sizeof(*tcpcon));
  tcpcon->timeout_connection = connection_timeout;
  if (tcpcon->timeout_connection == 0) {
    tcpcon->timeout_connection = 30; /* half a minute before destroying tcb */
  }
  tcpcon->timeout_hello = 2;
  tcpcon->entropy = entropy;

  /* Find nearest power of 2 to the tcb count, but don't go
   * over the number 16-million */
  {
    size_t new_entry_count;
    new_entry_count = 1;
    while (new_entry_count < entry_count) {
      new_entry_count *= 2;
      if (new_entry_count == 0) {
        new_entry_count = (1 << 24);
        break;
      }
    }
    if (new_entry_count > (1 << 24))
      new_entry_count = (1 << 24);
    if (new_entry_count < (1 << 10))
      new_entry_count = (1 << 10);
    entry_count = new_entry_count;
  }

  /* Create the table. If we can't allocate enough memory, then shrink
   * the desired size of the table */
  size_entries = 0;
  while (tcpcon->entries == NULL) {
    size_entries = entry_count * sizeof(*tcpcon->entries);
    tcpcon->entries = malloc(size_entries);
    if (tcpcon->entries == NULL) {
      entry_count >>= 1;
    }
  }
  memset(tcpcon->entries, 0, size_entries);

  /* fill in the table structure */
  tcpcon->count = entry_count;
  tcpcon->mask = entry_count - 1;

  /* create an event/timeouts structure */
  tcpcon->timeouts = timeouts_create(TICKS_FROM_SECS(time(0)));

  tcpcon->pkt_template = pkt_template;
  tcpcon->stack = stack;

  tcpcon->banner1 = banner1_create();

  tcpcon->report_status = report_status;
  tcpcon->report_banner = report_banner;
  tcpcon->report_sign = report_sign;
  tcpcon->ssl_key = ssl_key;

  tcpcon->out = out;
  return tcpcon;
}

static int EQUALS(const struct TCP_Control_Block *lhs,
                  const struct TCP_Control_Block *rhs) {
  if (lhs->port_me != rhs->port_me || lhs->port_them != rhs->port_them)
    return 0;
  if (lhs->ip_me.version != rhs->ip_me.version)
    return 0;
  if (lhs->ip_me.version == 6) {
    if (memcmp(&lhs->ip_me.ipv6, &rhs->ip_me.ipv6, sizeof(rhs->ip_me.ipv6)) !=
        0)
      return 0;
    if (memcmp(&lhs->ip_them.ipv6, &rhs->ip_them.ipv6,
               sizeof(rhs->ip_them.ipv6)) != 0)
      return 0;
  } else {
    if (lhs->ip_me.ipv4 != rhs->ip_me.ipv4)
      return 0;
    if (lhs->ip_them.ipv4 != rhs->ip_them.ipv4)
      return 0;
  }

  return 1;
}

/***************************************************************************
 ***************************************************************************/
static unsigned tcb_hash(const ipaddress *ip_me, unsigned port_me,
                         const ipaddress *ip_them, unsigned port_them,
                         uint64_t entropy) {

  unsigned index;
  /* TCB hash table uses symmetric hash, so incoming/outgoing packets
   * get the same hash. */
  if (ip_me->version == 6) {
    ipv6address_t ipv6 = ip_me->ipv6;
    ipv6.hi ^= ip_them->ipv6.hi;
    ipv6.lo ^= ip_them->ipv6.lo;
    index = (unsigned)syn_cookie_ipv6(&ipv6, port_me ^ port_them, &ipv6,
                                      port_me ^ port_them, entropy);

  } else {
    ipv4address_t ipv4 = ip_me->ipv4;
    ipv4 ^= ip_them->ipv4;
    index = (unsigned)syn_cookie_ipv4(&ipv4, port_me ^ port_them, &ipv4,
                                      port_me ^ port_them, entropy);
  }
  return index;
}

enum DestroyReason {
  Reason_Timeout = 1,
  Reason_FIN = 2,
  Reason_RST = 3,
  Reason_Foo = 4,
  Reason_Shutdown = 5,
  Reason_StateDone = 6,
};

/***************************************************************************
 * Flush all the banners associated with this TCP connection. This always
 * called when TCB is destroyed. This may also be called earlier, such
 * as when a FIN is received.
 ***************************************************************************/
static void tcpcon_flush_banners(struct TCP_ConnectionTable *tcpcon,
                                 struct TCP_Control_Block *tcb) {

  struct BannerOutput *banout;

  /* Go through and print all the banners. Some protocols have
   * multiple banners. For example, web servers have both
   * HTTP and HTML banners, and SSL also has several
   * X.509 certificate banners */
  for (banout = &tcb->banout; banout != NULL; banout = banout->next) {
    if (banout->length && banout->protocol) {
      tcpcon->report_banner(tcpcon->out, global_now, &tcb->ip_them,
                            6, /*TCP protocol*/
                            tcb->port_them, banout->protocol & 0x0FFFFFFF,
                            tcb->ttl, banout->banner, banout->length);
    }
  }
}

static void tcpcon_flush_status(struct TCP_ConnectionTable *tcpcon,
                                struct TCP_Control_Block *tcb) {

  struct StatusOutput *statout;

  for (statout = &tcb->statout; statout != NULL; statout = statout->next) {
    if (statout->is_empty == false) {
      tcpcon->report_status(tcpcon->out, statout->timestamp, statout->status,
                            &tcb->ip_them, 6, /*TCP protocol*/
                            tcb->port_them, statout->reason, statout->ttl,
                            statout->mac);
    }
  }
}

static void tcpcon_flush_sign(struct TCP_ConnectionTable *tcpcon,
                              struct TCP_Control_Block *tcb) {

  struct SignOutput *signout;

  for (signout = &tcb->signout; signout != NULL; signout = signout->next) {
    if (signout->is_empty == false) {
      tcpcon->report_sign(tcpcon->out, signout->timestamp, &tcb->ip_them,
                          6 /*TCP protocol*/, tcb->port_them,
                          signout->app_proto);
    }
  }
}

static void tcpcon_flush_key(struct TCP_ConnectionTable *tcpcon,
                             struct TCP_Control_Block *tcb) {

  struct KeyOutput *keyout;

  for (keyout = tcb->keyout; keyout != NULL; keyout = keyout->next) {
    tcpcon->ssl_key(tcpcon->out, keyout->line);
  }
}

/***************************************************************************
 * Destroy a TCP connection entry. We have to unlink both from the
 * TCB-table as well as the timeout-table.
 * Called from
 ***************************************************************************/
static void tcpcon_destroy_tcb(struct TCP_ConnectionTable *tcpcon,
                               struct TCP_Control_Block *tcb,
                               enum DestroyReason reason) {

  size_t index;
  struct TCP_Control_Block **r_entry;
  ipaddress_formatted_t fmt;

  UNUSEDPARM(reason);

  ipaddress_fmt(&fmt, &tcb->ip_them);
  LOG(LEVEL_INFO, "%s %u - closing\n", fmt.string, tcb->port_them);

  /* The TCB doesn't point to it's location in the table. Therefore, we
   * have to do a lookup to find the head pointer in the table. */
  index = (size_t)tcb_hash(&tcb->ip_me, tcb->port_me, &tcb->ip_them,
                           tcb->port_them, tcpcon->entropy);
  /* At this point, we have the head of a linked list of TCBs. Now,
   * traverse that linked list until we find our TCB */
  r_entry = &tcpcon->entries[index & tcpcon->mask];
  while (*r_entry && *r_entry != tcb)
    r_entry = &(*r_entry)->next;

  if (*r_entry == NULL) {
    /* TODO: this should be impossible, but it's happening anyway, about
     * 20 times on a full Internet scan. I don't know why, and I'm too
     * lazy to fix it right now, but I'll get around to eventually */
    LOG(LEVEL_WARNING, "tcb: double free\n");
    return;
  }

  if (tcpcon->banner1->regex == NULL) {
    tcpcon_flush_status(tcpcon, tcb);
    tcpcon_flush_sign(tcpcon, tcb);
    tcpcon_flush_key(tcpcon, tcb);
    /* Print out any banners associated with this TCP session. Most of the
     * time, there'll only be one. After printing them out, delete the
     * banners. */
    tcpcon_flush_banners(tcpcon, tcb);
  } else {
    if (tcb->banner1_state.is_check_regexp ||
        tcpcon->banner1->is_regex_only_banners) {
      tcpcon_flush_status(tcpcon, tcb);
      tcpcon_flush_sign(tcpcon, tcb);
      tcpcon_flush_key(tcpcon, tcb);
    }
    if (tcb->banner1_state.is_check_regexp) {
      tcpcon_flush_banners(tcpcon, tcb);
    }
  }
  /* Free up all the banners.*/
  signout_release(&tcb->signout);
  statout_release(&tcb->statout);
  banout_release(&tcb->banout);
  keyout_release(&tcb->keyout);

  if (tcb->payload.is_dynamic && tcb->payload.data_length &&
      tcb->payload.data) {
    free((void *)tcb->payload.data);
  }
  tcb->payload.data = NULL;
  tcb->payload.data_length = 0;
  tcb->payload.is_dynamic = false;

  if (tcb->scripting_thread)
    ; // scripting_thread_close(tcb->scripting_thread);
  tcb->scripting_thread = 0;

  cleanup_application_proto(tcpcon->banner1, &tcb->banner1_state,
                            &tcb->payload);

  /* Unlink this from the timeout system. */
  timeout_unlink(tcb->timeout);

  tcb->ip_them.ipv4 = (unsigned)~0;
  tcb->port_them = (unsigned short)~0;
  tcb->ip_me.ipv4 = (unsigned)~0;
  tcb->port_me = (unsigned short)~0;

  tcb->is_active = 0;

  (*r_entry) = tcb->next;
  tcb->next = tcpcon->freed_list;
  tcpcon->freed_list = tcb;
  tcpcon->active_count--;
}

/***************************************************************************
 * Called at shutdown to free up all the memory used by the TCP
 * connection table.
 ***************************************************************************/
void tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon) {
  size_t i;

  if (tcpcon == NULL)
    return;

  /* Do a graceful destruction of all the entires. If they have banners,
   * they will be sent to the output */
  for (i = 0; i <= tcpcon->mask; i++) {
    while (tcpcon->entries[i]) {
      tcpcon_destroy_tcb(tcpcon, tcpcon->entries[i], Reason_Shutdown);
    }
  }

  /* Now free the memory */
  while (tcpcon->freed_list) {
    struct TCP_Control_Block *tcb = tcpcon->freed_list;
    tcpcon->freed_list = tcb->next;
    free(tcb);
  }

  banner1_destroy(tcpcon->banner1);
  tcpcon->banner1 = NULL;
  timeouts_destroy(tcpcon->timeouts);
  tcpcon->timeouts = NULL;
  free(tcpcon->entries);
  free(tcpcon);
}

/***************************************************************************
 * Called when we receive a "SYN-ACK" packet with the correct SYN-cookie.
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_create_tcb(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_me,
                  const ipaddress *ip_them, unsigned port_me,
                  unsigned port_them, unsigned seqno_me, unsigned seqno_them,
                  unsigned ttl) {
  size_t index;
  struct TCP_Control_Block tmp;
  struct TCP_Control_Block *tcb;

  assert(ip_me->version != 0 && ip_them->version != 0);

  tmp.ip_me = *ip_me;
  tmp.ip_them = *ip_them;
  tmp.port_me = (unsigned short)port_me;
  tmp.port_them = (unsigned short)port_them;

  index = (size_t)tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);

  tcb = tcpcon->entries[index & tcpcon->mask];
  while (tcb && !EQUALS(tcb, &tmp)) {
    tcb = tcb->next;
  }
  if (tcb == NULL) {
    if (tcpcon->freed_list) {
      tcb = tcpcon->freed_list;
      tcpcon->freed_list = tcb->next;
    } else {
      tcb = MALLOC(sizeof(*tcb));
    }
    memset(tcb, 0, sizeof(*tcb));
    tcb->next = tcpcon->entries[index & tcpcon->mask];
    tcpcon->entries[index & tcpcon->mask] = tcb;

    tcb->ip_me = *ip_me;
    tcb->ip_them = *ip_them;
    tcb->port_me = (unsigned short)port_me;
    tcb->port_them = (unsigned short)port_them;

    tcb->seqno_them_first = seqno_them; /* ipv6-todo */
    tcb->seqno_me = seqno_me;
    tcb->seqno_them = seqno_them;
    tcb->ackno_me = seqno_them;
    tcb->ackno_them = seqno_me;
    tcb->when_created = global_now;
    tcb->banner1_state.port = tmp.port_them;
    tcb->banner1_state.ip = tmp.ip_them;
    tcb->ttl = (unsigned char)ttl;

    timeout_init(tcb->timeout);
    keyout_init(&tcb->keyout);
    signout_init(&tcb->signout);
    statout_init(&tcb->statout);
    banout_init(&tcb->banout);

    /* The TCB is now allocated/in-use */
    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);
    tcb->is_active = 1;

    tcpcon->active_count++;
  }

  tcb_lookup(tcpcon, ip_me, ip_them, port_me, port_them);

  return tcb;
}

/***************************************************************************
 ***************************************************************************/
struct TCP_Control_Block *tcb_lookup(struct TCP_ConnectionTable *tcpcon,
                                     const ipaddress *ip_me,
                                     const ipaddress *ip_them, unsigned port_me,
                                     unsigned port_them) {

  size_t index;
  struct TCP_Control_Block tmp;
  struct TCP_Control_Block *tcb;
  ipaddress_formatted_t fmt1;
  ipaddress_formatted_t fmt2;

  tmp.ip_me = *ip_me;
  tmp.ip_them = *ip_them;
  tmp.port_me = (unsigned short)port_me;
  tmp.port_them = (unsigned short)port_them;

  index = (size_t)tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);

  ipaddress_fmt(&fmt1, ip_me);
  ipaddress_fmt(&fmt2, ip_them);
  LOG(LEVEL_INFO, "tcb_hash(0x%08" PRIx64 ") = %s %u %s %u\n", index,
      fmt1.string, port_me, fmt2.string, port_them);

  /* Hash to an entry in the table, then follow a linked list from
   * that point forward. */
  tcb = tcpcon->entries[index & tcpcon->mask];
  while (tcb && !EQUALS(tcb, &tmp)) {
    tcb = tcb->next;
  }

  return tcb;
}

/***************************************************************************
 ***************************************************************************/
static void tcpcon_send_packet(struct TCP_ConnectionTable *tcpcon,
                               struct TCP_Control_Block *tcb,
                               unsigned tcp_flags, unsigned char *payload,
                               size_t payload_length,
                               unsigned is_payload_dynamic, unsigned ctrl) {
  struct PacketBufferTransmit *response;

  assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

  /* Get a buffer for sending the response packet. This thread doesn't
   * send the packet itself. Instead, it formats a packet, then hands
   * that packet off to a transmit thread for later transmission. */
  response = stack_get_transmit_packetbuffer(tcpcon->stack);
  if (response == NULL) {
    static int is_warning_printed = 0;
    if (!is_warning_printed) {
      LOG(LEVEL_ERROR, "packet buffers empty (should be impossible)\n");
      is_warning_printed = 1;
    }
    /* FIXME: I'm no sure the best way to handle this.
     * This would result from a bug in the code,
     * but I'm not sure what should be done in response */
    pixie_usleep(100); /* no packet available */
  }
  if (response == NULL) {
    LOG(LEVEL_WARNING, "Can't get response from packet_buffers\n");
    return;
  }

  /* Format the packet as requested. Note that there are really only
   * four types of packets:
   * 1. a SYN-ACK packet with no payload
   * 2. an ACK packet with no payload
   * 3. a RST packet with no payload
   * 4. a PSH-ACK packet WITH PAYLOAD */
  response->length = tcp_create_packet(
      tcpcon->pkt_template, &tcb->ip_them, tcb->port_them, &tcb->ip_me,
      tcb->port_me, tcb->seqno_me, tcb->seqno_them, tcp_flags, payload,
      payload_length, response->px, sizeof(response->px));

  /* KLUDGE: */
  if (ctrl & CTRL_SMALL_WINDOW) {
    tcp_set_window(response->px, response->length, 600);
  }
  // tcp_set_window(response->px, response->length, 600);

  /* If we have payload, then:
   * 1. remember the payload so we can resend it */
  if (tcb->payload.data == NULL) {
    tcb->payload.data = payload;
    tcb->payload.data_length = (unsigned short)payload_length;
    tcb->payload.is_dynamic = is_payload_dynamic;
  } else if (payload == NULL || payload_length == 0) {
    // pass
  } else {
    size_t size_new_payload = payload_length + tcb->payload.data_length;
    unsigned char *new_payload = malloc(size_new_payload);
    if (new_payload == NULL) {
      LOG(LEVEL_WARNING, "Out of memory\n");
    } else {
      memcpy((void *)new_payload, tcb->payload.data, tcb->payload.data_length);
      memcpy((void *)(new_payload + tcb->payload.data_length), payload,
             payload_length);
      if (tcb->payload.is_dynamic) {
        free((void *)tcb->payload.data);
      }
      tcb->payload.data = new_payload;
      assert(payload_length + tcb->payload.data_length < USHRT_MAX);
      tcb->payload.data_length =
          (unsigned short)(payload_length + tcb->payload.data_length);
      tcb->payload.is_dynamic = true;
    }
    if (is_payload_dynamic) {
      free((void *)payload);
    }
  }

  /* Put this buffer on the transmit queue. Remember: transmits happen
   * from a transmit-thread only, and this function is being called
   * from a receive-thread. Therefore, instead of transmiting ourselves,
   * we hae to queue it up for later transmission. */
  stack_transmit_packetbuffer(tcpcon->stack, response);
}

/***************************************************************************
 ***************************************************************************/
void tcp_send_RST(struct TemplatePacket *templ, struct stack_t *stack,
                  const ipaddress *ip_them, const ipaddress *ip_me,
                  unsigned port_them, unsigned port_me, unsigned seqno_them,
                  unsigned seqno_me) {
  struct PacketBufferTransmit *response;

  /* Get a buffer for sending the response packet. This thread doesn't
   * send the packet itself. Instead, it formats a packet, then hands
   * that packet off to a transmit thread for later transmission. */
  response = stack_get_transmit_packetbuffer(stack);
  if (response == NULL) {
    static int is_warning_printed = 0;
    if (!is_warning_printed) {
      LOG(LEVEL_WARNING, "packet buffers empty (should be impossible)\n");
      is_warning_printed = 1;
    }
    pixie_usleep(100); /* no packet available */
  }

  if (response == NULL) {
    return;
  }

  response->length = tcp_create_packet(
      templ, ip_them, port_them, ip_me, port_me, seqno_me, seqno_them, TH_RST,
      NULL, 0, response->px, sizeof(response->px));

  /* Put this buffer on the transmit queue. Remember: transmits happen
   * from a transmit-thread only, and this function is being called
   * from a receive-thread. Therefore, instead of transmitting ourselves,
   * we have to queue it up for later transmission. */
  stack_transmit_packetbuffer(stack, response);
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *state_to_string(int state) {
  static char buf[64];
  switch (state) {
    // STATE_SYN_RECEIVED,
    // STATE_CLOSE_WATI,
  case STATE_LAST_ACK:
    return "LAST-ACK";
  case STATE_FIN_WAIT1:
    return "FIN-WAIT-1";
  case STATE_FIN_WAIT2:
    return "FIN-WAIT-2";
  case STATE_CLOSING:
    return "CLOSING";
  case STATE_TIME_WAIT:
    return "TIME-WAIT";
  case STATE_SYN_SENT:
    return "SYN_SENT";
  case STATE_ESTABLISHED_SEND:
    return "ESTABLISHED_SEND";
  case STATE_ESTABLISHED_RECV:
    return "ESTABLISHED_RECV";

  default:
    sprintf_s(buf, sizeof(buf), "%d", state);
    return buf;
  }
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *what_to_string(enum TCP_What state) {
  static char buf[64];
  switch (state) {
  case TCP_WHAT_TIMEOUT:
    return "TIMEOUT";
  case TCP_WHAT_SYNACK:
    return "SYNACK";
  case TCP_WHAT_RST:
    return "RST";
  case TCP_WHAT_FIN:
    return "FIN";
  case TCP_WHAT_ACK:
    return "ACK";
  case TCP_WHAT_DATA:
    return "DATA";
  case TCP_WHAT_DATA_END:
    return "DATA_END";
  default:
    sprintf_s(buf, sizeof(buf), "%d", state);
    return buf;
  }
}

/***************************************************************************
 ***************************************************************************/

static void LOGSEND(struct TCP_Control_Block *tcb, const char *what) {
  if (tcb == NULL)
    return;
  LOGip(LEVEL_DEBUG_3, &tcb->ip_them, tcb->port_them,
        "=%s : --->> %s                  \n", state_to_string(tcb->tcpstate),
        what);
}

/***************************************************************************
 * Sends a fake FIN when we've already closed our connection, on the
 * assumption this will help the other side close their side more
 * gracefully. Maybe we should do a RST instead.
 ***************************************************************************/
void tcpcon_send_FIN(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_me,
                     const ipaddress *ip_them, unsigned port_me,
                     unsigned port_them, uint32_t seqno_them,
                     uint32_t ackno_them) {
  struct TCP_Control_Block tcb;

  memset(&tcb, 0, sizeof(tcb));

  tcb.ip_me = *ip_me;
  tcb.ip_them = *ip_them;
  tcb.port_me = (unsigned short)port_me;
  tcb.port_them = (unsigned short)port_them;
  tcb.seqno_me = ackno_them;
  tcb.ackno_me = seqno_them + 1;
  tcb.seqno_them = seqno_them + 1;
  tcb.ackno_them = ackno_them;

  LOGSEND(&tcb, "peer(FIN) fake");
  tcpcon_send_packet(tcpcon, &tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);
}

void tcpcon_send_RST(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_me,
                     const ipaddress *ip_them, unsigned port_me,
                     unsigned port_them, uint32_t seqno_them,
                     uint32_t ackno_them) {

  struct TCP_Control_Block tcb;

  memset(&tcb, 0, sizeof(tcb));
  tcb.ip_me = *ip_me;
  tcb.ip_them = *ip_them;
  tcb.port_me = (unsigned short)port_me;
  tcb.port_them = (unsigned short)port_them;
  tcb.seqno_me = ackno_them;
  tcb.ackno_me = seqno_them + 1;
  tcb.seqno_them = seqno_them + 1;
  tcb.ackno_them = ackno_them;

  LOGSEND(&tcb, "send RST");
  tcpcon_send_packet(tcpcon, &tcb, TH_RST, NULL, 0, false, 0);
}

/***************************************************************************
 ***************************************************************************/
static int handle_ack(struct TCP_Control_Block *tcb, uint32_t ackno) {

  /* LOG(LEVEL_DEBUG_2, "%s - %u-sending, %u-reciving\n",
              fmt.string, tcb->seqno_me - ackno, ackno - tcb->ackno_them); */

  /* Normal: just discard repeats */
  if (ackno == tcb->ackno_them) {
    return 0;
  }

  /* Make sure this isn't a duplicate ACK from past
   * WRAPPING of 32-bit arithmetic happens here */
  if (ackno - tcb->ackno_them > 10000) {
    ipaddress_formatted_t fmt;
    ipaddress_fmt(&fmt, &tcb->ip_them);
    LOG(LEVEL_DEBUG_2,
        "%s - tcb: ackno from past: "
        "old ackno = 0x%08x, this ackno = 0x%08x\n",
        fmt.string, tcb->ackno_me, ackno);
    return 0;
  }

  /* Make sure this isn't invalid ACK from the future
   * WRAPPING of 32-bit arithmetic happens here */
  if (tcb->seqno_me - ackno > 10000) {
    ipaddress_formatted_t fmt;
    ipaddress_fmt(&fmt, &tcb->ip_them);
    LOG(LEVEL_DEBUG_2,
        "%s - tcb: ackno from future: "
        "my seqno = 0x%08x, their ackno = 0x%08x\n",
        fmt.string, tcb->seqno_me, ackno);
    return 0;
  }
  /* now that we've verified this is a good ACK, record this number */
  tcb->ackno_them = ackno;
  /* Mark that this was a good ack */
  return 1;
}

enum AppAction {
  APP_CONNECTED,
  APP_RECV_TIMEOUT,
  APP_RECV_PAYLOAD,
  APP_RECV_PAYLOAD_END,
  APP_SEND_SENT,
};

void init_application_proto(const struct Banner1 *banner1,
                            struct ProtocolState *pstate,
                            struct ResendPayload *resend_payload,
                            struct BannerOutput *banout,
                            struct KeyOutput **keyout) {

  if (pstate->parser_stream && pstate->parser_stream->transmit_init) {
    pstate->parser_stream->transmit_init(banner1, pstate, resend_payload,
                                         banout, keyout);
  }
}

void cleanup_application_proto(const struct Banner1 *banner1,
                               struct ProtocolState *pstate,
                               struct ResendPayload *resend_payload) {

  if (pstate->parser_stream && pstate->parser_stream->transmit_cleanup) {
    pstate->parser_stream->transmit_cleanup(banner1, pstate, resend_payload);
  }
}

void switch_application_proto(
    const struct Banner1 *banner1, struct ProtocolState *pstate,
    struct ResendPayload *resend_payload, struct BannerOutput *banout,
    struct KeyOutput **keyout, unsigned short new_proto,
    const struct ProtocolParserStream *new_parser_stream) {

  unsigned short port = pstate->port;
  ipaddress ip = pstate->ip;

  LOG(LEVEL_DEBUG, "[switch_application_proto] %uh -> %uh\n", pstate->app_proto,
      new_proto);
  assert(pstate->parser_stream != new_parser_stream);

  cleanup_application_proto(banner1, pstate, resend_payload);

  memset(pstate, 0, sizeof(*pstate));
  pstate->app_proto = new_proto;
  pstate->parser_stream = new_parser_stream;
  pstate->port = (unsigned short)port;
  pstate->ip = ip;

  init_application_proto(banner1, pstate, resend_payload, banout, keyout);
}

/***************************************************************************
 ***************************************************************************/
void application_receive_hello(const struct Banner1 *banner1,
                               struct ProtocolState *tcb_state,
                               struct ResendPayload *resend_payload,
                               struct BannerOutput *banout,
                               struct KeyOutput **keyout,
                               struct InteractiveData *more) {

  const struct ProtocolParserStream *parser_stream = tcb_state->parser_stream;

  if (parser_stream->transmit_hello)
    parser_stream->transmit_hello(banner1, tcb_state, resend_payload, banout,
                                  keyout, more);
  else {
    more->m_length = (unsigned)parser_stream->hello_length;
    more->m_payload = parser_stream->hello;
    more->is_payload_dynamic = 0;
  }

  /* Kludge */
  if (parser_stream->proto == PROTO_SSL3) {
    tcb_state->is_sent_sslhello = 1;
  }

  /* KLUDGE */
  if (banner1->is_heartbleed) {
    more->tcp_ctrl = CTRL_SMALL_WINDOW;
  }
}

void application_receive_next(
    const struct Banner1 *banner1, struct ProtocolState *main_tcb_state,
    struct ProtocolState *tcb_state, struct ResendPayload *resend_payload,
    const void *payload, size_t payload_length, struct BannerOutput *banout,
    struct SignOutput *signout, struct KeyOutput **keyout,
    struct InteractiveData *more) {

  struct InteractiveData more_heur = {0};
  enum ApplicationProtocol app_proto;
  int ovector[3];
  int regex_count = 0;
  /* [--banners]
   * This is an important part of the system, where the TCP
   * stack passes incoming packet payloads off to the application
   * layer protocol parsers. This is where, in Sockets API, you
   * might call the 'recv()' function.
   */
  if (banner1->regex && main_tcb_state->is_check_regexp == 0) {
    regex_count = pcre_exec(banner1->regex, banner1->regex_extra, payload,
                            (int)payload_length, 0, 0, ovector, 3);
    if (regex_count > 0) {
      main_tcb_state->is_check_regexp = 1;
    }
  }

  assert(banout->max_length);

  if (tcb_state->app_proto == PROTO_NONE ||
      tcb_state->app_proto == PROTO_HEUR) {
    app_proto =
        banner1_detect_proto(banner1, tcb_state, payload, payload_length);
    LOG(LEVEL_INFO, "Detect protot %u\n", app_proto);
    if (app_proto == PROTO_NONE || app_proto == PROTO_HEUR) {
      banout_append(banout, PROTO_HEUR, payload, payload_length);
      return;
    } else {
      const unsigned char *s;
      size_t s_len;

      signout_new_sign(signout, global_now, app_proto);

      tcb_state->app_proto = app_proto;
      tcb_state->parser_stream =
          banner1_get_parse_stream_by_app_proto(banner1, app_proto);
      tcb_state->state = 0;

      init_application_proto(banner1, tcb_state, resend_payload, banout,
                             keyout);

      s = banout_string(banout, PROTO_HEUR);
      s_len = banout_string_length(banout, PROTO_HEUR);

      if (s && s_len) {
        if (tcb_state->parser_stream != NULL) {
          tcb_state->parser_stream->transmit_parse(
              banner1, banner1->http_fields, tcb_state, resend_payload, s,
              s_len, banout, signout, keyout, &more_heur);
        }
        banout_detach_by_proto(banout, PROTO_HEUR);
      }
    }
  }

  if (tcb_state->parser_stream == NULL) {
    free_interactive_data(&more_heur);
    return;
  }

  tcb_state->parser_stream->transmit_parse(
      banner1, banner1->http_fields, tcb_state, resend_payload, payload,
      payload_length, banout, signout, keyout, more);
  append_interactive_data(more, &more_heur);
}

static void application(struct TCP_ConnectionTable *tcpcon,
                        struct TCP_Control_Block *tcb, enum AppAction action,
                        const void *payload, size_t payload_length,
                        unsigned secs, unsigned usecs, unsigned *pis_send_ack) {

  struct Banner1 *banner1 = tcpcon->banner1;
  enum { App_Connect, App_ReceiveHello, App_ReceiveNext, App_SendNext };

  *pis_send_ack = false;

  switch (tcb->established) {
  case App_Connect:
    if (banner1->payloads.tcp[tcb->port_them] == &banner_scripting) {
      // int x;
      ; // tcb->scripting_thread = scripting_thread_new(tcpcon->scripting_vm);
      ; // x = scripting_thread_run(tcb->scripting_thread);
    } else {
      /*
       * Wait 1 second for "server hello" (like SSH), and if that's
       * not found, then transmit a "client hello"
       */
      assert(action == APP_CONNECTED);
      LOGSEND(tcb, "+timeout");
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV(secs + tcpcon->timeout_hello, usecs));
      /* Start of connection */
      tcb->tcpstate = STATE_ESTABLISHED_RECV;
      tcb->established = App_ReceiveHello;
    }
    break;
  case App_ReceiveHello:
    if (action == APP_RECV_TIMEOUT) {
      if (tcb->banner1_state.parser_stream == NULL) {
        tcb->banner1_state.parser_stream =
            banner1->payloads.tcp[tcb->port_them];
        if (tcb->banner1_state.parser_stream != NULL &&
            tcb->banner1_state.parser_stream->proto == PROTO_SSL3) {
          tcb->banner1_state.parser_stream = get_ssl_parser_stream(banner1);
        }
        init_application_proto(banner1, &tcb->banner1_state, &tcb->payload,
                               &tcb->banout, &tcb->keyout);
      } else {
        // resend hello data by timeout
      }
      if (tcb->banner1_state.parser_stream) {
        struct InteractiveData more = {0};
        tcb->banner1_state.app_proto = tcb->banner1_state.parser_stream->proto;
        application_receive_hello(banner1, &tcb->banner1_state, &tcb->payload,
                                  &tcb->banout, &tcb->keyout, &more);
        /* Queue up the packet to be sent */
        LOGip(LEVEL_DEBUG_2, &tcb->ip_them, tcb->port_them,
              "sending payload %u bytes\n", more.m_length);
        LOGSEND(tcb, "peer(ACK|TH_PUSH)");
        LOGSEND(tcb, "peer(payload)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_PUSH, more.m_payload,
                           (size_t)more.m_length, more.is_payload_dynamic,
                           more.tcp_ctrl);
        *pis_send_ack = true;
        tcb->seqno_me += (uint32_t)more.m_length;
        tcb->tcpstate = STATE_ESTABLISHED_SEND;
        // tcb->established = App_SendNext;
      }

      /* Add a timeout so that we can resend the data in case it
       * goes missing. Note that we put this back in the timeout
       * system regardless if we've sent data. */
      LOGSEND(tcb, "+timeout");
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV((uint64_t)secs + 1, usecs));
      break;
    } else if (action == APP_RECV_PAYLOAD || action == APP_RECV_PAYLOAD_END) {
      tcb->established = App_ReceiveNext;
      /* fall through */
    }
    /* fall through */
  case App_ReceiveNext:
    if (action == APP_RECV_PAYLOAD || action == APP_RECV_PAYLOAD_END) {
      unsigned int tcp_flags = 0;
      struct InteractiveData more = {0};

      application_receive_next(tcpcon->banner1, &tcb->banner1_state,
                               &tcb->banner1_state, &tcb->payload, payload,
                               payload_length, &tcb->banout, &tcb->signout,
                               &tcb->keyout, &more);

      /* move their sequence number forward */
      tcb->seqno_them += (unsigned)payload_length;
      if (action == APP_RECV_PAYLOAD_END) {
        tcb->seqno_them++;
      }
      if (more.is_closing || action == APP_RECV_PAYLOAD_END) {
        /* Send FIN packet */
        LOGSEND(tcb, "peer(FIN)(App_ReceiveNext)");
        tcp_flags = TH_FIN;
      }

      /* acknowledge the bytes received */
      if (more.m_length) {
        // printf("." "sending more data %u bytes\n", more.length);
        LOGSEND(tcb, "peer(ACK|TH_PUSH)(App_ReceiveNext)");
        LOGSEND(tcb, "peer(payload)");
        tcp_flags = tcp_flags | TH_ACK | TH_PUSH;
        tcpcon_send_packet(tcpcon, tcb, tcp_flags, more.m_payload,
                           (size_t)more.m_length, more.is_payload_dynamic, 0);

        tcb->seqno_me += (uint32_t)more.m_length;
        tcb->tcpstate = STATE_ESTABLISHED_SEND;
        tcb->established = App_SendNext;
        LOGip(LEVEL_DEBUG_2, &tcb->ip_them, tcb->port_them,
              "sending payload %u bytes\n", more.m_length);
      } else {
        LOGSEND(tcb, "peer(ACK)(App_ReceiveNext)");
        tcp_flags = tcp_flags | TH_ACK;
        tcpcon_send_packet(tcpcon, tcb, tcp_flags, NULL, 0, false, 0);
      }

      *pis_send_ack = true;
      if (more.is_closing || action == APP_RECV_PAYLOAD_END) {
        tcb->tcpstate = STATE_FIN_WAIT2;
        tcb->seqno_me++;
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 1, usecs));
        // tcpcon_destroy_tcb(tcpcon, tcb, Reason_StateDone);
      }
    }
    break;
  case App_SendNext:
    if (action == APP_SEND_SENT) {
      tcb->tcpstate = STATE_ESTABLISHED_RECV;
      tcb->established = App_ReceiveNext;
    }
    break;
  default:
    LOG(LEVEL_ERROR, "TCP state error\n");
    exit(1);
    break;
  }
}

/*****************************************************************************
 * Handles incoming events, like timeouts and packets, that cause a change
 * in the TCP control block "state".
 *
 * This is the part of the code that implements the famous TCP state-machine
 * you see drawn everywhere, where they have states like "TIME_WAIT". Only
 * we don't really have those states.
 *****************************************************************************/
int stack_incoming_tcp(struct TCP_ConnectionTable *tcpcon,
                       struct TCP_Control_Block *tcb, int in_what,
                       const void *vpayload, size_t payload_length,
                       unsigned secs, unsigned usecs, unsigned seqno_them) {
  enum TCP_What what = in_what;
  const unsigned char *payload = (const unsigned char *)vpayload;
  unsigned is_send_ack = false;

  if (tcb == NULL) {
    return 0;
  }

  LOGip(LEVEL_DEBUG_3, &tcb->ip_them, tcb->port_them,
        "=%s : %s                  \n", state_to_string(tcb->tcpstate),
        what_to_string(what));

  /* Make sure no connection lasts more than ~30 seconds */
  if (what == TCP_WHAT_TIMEOUT) {
    if (tcb->when_created + tcpcon->timeout_connection < (time_t)secs) {
      LOGip(LEVEL_DEBUG_5, &tcb->ip_them, tcb->port_them,
            "%s                \n", "CONNECTION TIMEOUT---");
      LOGSEND(tcb, "peer(RST)");
      tcpcon_send_packet(tcpcon, tcb, TH_RST, NULL, 0, false, 0);
      tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
      return 1;
    }
  }

  if (what == TCP_WHAT_RST) {
    LOGSEND(tcb, "tcb(destroy)");
    tcpcon_destroy_tcb(tcpcon, tcb, Reason_RST);
    return 1;
  }

  switch (tcb->tcpstate) {
    /* TODO: validate any SYNACK is real before sending it here
     * to the state-machine, by validating that it's acking
     * something */
  case STATE_SYN_SENT:
    switch (what) {
    case TCP_WHAT_RST:
    case TCP_WHAT_TIMEOUT:
    // case TCP_WHAT_SYNACK:
    case TCP_WHAT_FIN:
    case TCP_WHAT_ACK:
    case TCP_WHAT_DATA:
    case TCP_WHAT_DATA_END:
      break;
    case TCP_WHAT_SYNACK:
      /* Send "ACK" to acknowlege their "SYN-ACK" */
      LOGSEND(tcb, "peer(ACK) [acknowledge SYN-ACK 1] (TCP_WHAT_SYNACK)");
      tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, 0, false);
      LOGSEND(tcb, "app(connected)");
      application(tcpcon, tcb, APP_CONNECTED, 0, 0, secs, usecs, &is_send_ack);
      break;
    }
    break;
  case STATE_ESTABLISHED_SEND:
  case STATE_ESTABLISHED_RECV:
    switch (what) {
    case TCP_WHAT_RST:
      break;
    case TCP_WHAT_SYNACK:
      /* Send "ACK" to acknowlege their "SYN-ACK" */
      LOGSEND(tcb, "peer(ACK) [acknowledge SYN-ACK 2] (TCP_WHAT_SYNACK)");
      tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, false, 0);
      break;
    case TCP_WHAT_FIN:
      if (tcb->tcpstate == STATE_ESTABLISHED_RECV) {
        tcb->seqno_them = seqno_them + 1;

        LOGSEND(tcb, "peer(ACK|FIN)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);
        tcb->seqno_me++;
        tcb->tcpstate = STATE_LAST_ACK;
      } else if (tcb->tcpstate == STATE_ESTABLISHED_SEND) {
        /* Do nothing, the same thing as if we received data
         * during the SEND state. The other side will send it
         * again after it has acknowledged our data */
        ;
      } else {
        assert(false);
      }
      break;
    case TCP_WHAT_ACK:
      /* There's actually nothing that goes on in this state. We are
       * just waiting for the timer to expire. In the meanwhile,
       * though, the other side is might acknowledge that we sent
       * a SYN-ACK */

      /* NOTE: the arg 'payload_length' was overloaded here to be the
       * 'ackno' instead */
      handle_ack(tcb, (uint32_t)payload_length);
      if (tcb->tcpstate == STATE_ESTABLISHED_SEND) {
        if (tcb->ackno_them - tcb->seqno_me == 0) {
          /* All the payload has been sent */
          if (tcb->payload.is_dynamic) {
            free((void *)tcb->payload.data);
          }
          tcb->payload.data = NULL;
          tcb->payload.data_length = 0;
          tcb->payload.is_dynamic = false;

          LOGSEND(tcb, "app(sent)");
          application(tcpcon, tcb, APP_SEND_SENT, 0, 0, secs, usecs,
                      &is_send_ack);
          tcb->tcpstate = STATE_ESTABLISHED_RECV;
          LOGSEND(tcb, "+timeout");
          timeouts_add(tcpcon->timeouts, tcb->timeout,
                       offsetof(struct TCP_Control_Block, timeout),
                       TICKS_FROM_TV((uint64_t)secs + 10, usecs));
        } else {
          /* Reset the timeout, waiting for more data to arrive */
          LOGSEND(tcb, "+timeout");
          timeouts_add(tcpcon->timeouts, tcb->timeout,
                       offsetof(struct TCP_Control_Block, timeout),
                       TICKS_FROM_TV((uint64_t)secs + 1, usecs));
        }
      }
      break;
    case TCP_WHAT_TIMEOUT:
      if (tcb->tcpstate == STATE_ESTABLISHED_RECV) {
        /* Didn't receive data in the expected timeframe. This is
         * often a normal condition, such as during the start
         * of a scanned connection, when we don't understand the
         * protocol and are simply waiting for anything the
         * server might send us.
         */
        LOGSEND(tcb, "app(timeout)");
        application(tcpcon, tcb, APP_RECV_TIMEOUT, 0, 0, secs, usecs,
                    &is_send_ack);
      } else if (tcb->tcpstate == STATE_ESTABLISHED_SEND) {
        /*
         * We did not get a complete ACK of our sent data, so retransmit
         * it to the server
         */
        uint32_t len;
        len = tcb->seqno_me - tcb->ackno_them;

        /* Resend the payload */
        tcb->seqno_me -= len;
        LOGSEND(tcb, "peer(payload) retransmit");
        LOGSEND(tcb, "peer(ACK|PSH)");

        /* kludge: should never be NULL< but somehow is */
        if (tcb->payload.data) {
          unsigned char *new_payload;
          unsigned is_payload_dynamic;
          assert(len <= tcb->payload.data_length);
          if (len == 0) {
            new_payload = NULL;
            is_payload_dynamic = false;
            if (tcb->payload.is_dynamic) {
              free((void *)tcb->payload.data);
            }
          } else if (len == tcb->payload.data_length ||
                     tcb->payload.is_dynamic == false) {
            new_payload = tcb->payload.data + tcb->payload.data_length - len;
            is_payload_dynamic = tcb->payload.is_dynamic;
          } else {
            new_payload = malloc((size_t)len);
            if (new_payload == NULL) {
              LOG(LEVEL_WARNING, "Out of memory\n");
              is_payload_dynamic = false;
              len = 0;
            } else {
              is_payload_dynamic = true;
              assert(new_payload != NULL);
              memcpy((void *)new_payload,
                     tcb->payload.data + tcb->payload.data_length - len,
                     (size_t)len);
            }
            free((void *)tcb->payload.data);
          }
          tcb->payload.data = NULL;
          tcb->payload.data_length = 0;
          tcb->payload.is_dynamic = false;
          tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_PUSH, new_payload,
                             (size_t)len, is_payload_dynamic, 0);
        }
        tcb->seqno_me += len;

        /* Now that we've resent the packet, register another
         * timeout in order to resend it yet again if not
         * acknowledged. */
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 2, usecs));
      }

      break;
    case TCP_WHAT_DATA:

      if ((size_t)(tcb->seqno_them - seqno_them) > payload_length) {
        LOGSEND(tcb, "peer(ACK) [acknowledge payload 1] (TCP_WHAT_DATA 1)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, false, 0);
        return 1;
      }

      while (seqno_them != tcb->seqno_them && payload_length) {
        seqno_them++;
        payload_length--;
        payload++;
      }

      if (payload_length == 0) {
        LOGSEND(tcb, "peer(ACK) [acknowledge empty data] (TCP_WHAT_DATA 2)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, false, 0);
        return 1;
      }
      LOGSEND(tcb, "app(payload)(TCP_WHAT_DATA)");
      application(tcpcon, tcb, APP_RECV_PAYLOAD, payload, payload_length, secs,
                  usecs, &is_send_ack);
      if (!is_send_ack) {
        /* Send ack for the data */
        LOGSEND(tcb, "peer(ACK)(TCP_WHAT_DATA 3)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, false, 0);
      }
      break;
    case TCP_WHAT_DATA_END:

      if ((size_t)(tcb->seqno_them - seqno_them) > payload_length) {
        tcb->seqno_them = seqno_them + 1;
        LOGSEND(tcb, "peer(ACK)(TCP_WHAT_DATA_END 1)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);
        tcb->seqno_me++;
        tcb->tcpstate = STATE_FIN_WAIT2;
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 5, usecs));
        return 1;
      }

      while (seqno_them != tcb->seqno_them && payload_length) {
        seqno_them++;
        payload_length--;
        payload++;
      }

      if (payload_length == 0) {
        tcb->seqno_them = seqno_them + 1;
        LOGSEND(tcb, "peer(ACK)(TCP_WHAT_DATA_END 2)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);
        tcb->seqno_me++;
        tcb->tcpstate = STATE_FIN_WAIT2;
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 5, usecs));
        return 1;
      }

      LOGSEND(tcb, "app(payload)(TCP_WHAT_DATA_END)");
      application(tcpcon, tcb, APP_RECV_PAYLOAD_END, payload, payload_length,
                  secs, usecs, &is_send_ack);
      if (!is_send_ack) {
        tcb->seqno_them = seqno_them + 1;
        /* Send ack for the data */
        LOGSEND(tcb, "peer(ACK)(TCP_WHAT_DATA_END 3)");
        tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);
        tcb->seqno_me++;
        tcb->tcpstate = STATE_FIN_WAIT2;
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 5, usecs));
      }
      break;
    }
    break;
  case STATE_FIN_WAIT1:
    switch (what) {
    case TCP_WHAT_TIMEOUT:
      /* resend FIN packet */
      LOGSEND(tcb, "peer(ACK|TH_FIN)");
      tcpcon_send_packet(tcpcon, tcb, TH_ACK | TH_FIN, NULL, 0, false, 0);

      /* reset timeout */
      LOGSEND(tcb, "+timeout");
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV((uint64_t)secs + 1, usecs));
      break;
    case TCP_WHAT_ACK:
      if (handle_ack(tcb, (uint32_t)payload_length)) {
        tcb->tcpstate = STATE_FIN_WAIT2;
        LOGSEND(tcb, "+timeout");
        timeouts_add(tcpcon->timeouts, tcb->timeout,
                     offsetof(struct TCP_Control_Block, timeout),
                     TICKS_FROM_TV((uint64_t)secs + 5, usecs));
      }
      break;
    case TCP_WHAT_FIN:
      // tcb->tcpstate = STATE_FIN_WAIT2;
      // LOGSEND(tcb, "+timeout");
      // timeouts_add(tcpcon->timeouts, tcb->timeout,
      //	offsetof(struct TCP_Control_Block, timeout),
      //	TICKS_FROM_TV(secs + 5, usecs));
      break;
    case TCP_WHAT_SYNACK:
    case TCP_WHAT_RST:
    case TCP_WHAT_DATA:
    case TCP_WHAT_DATA_END:
      break;
    }
    break;

  case STATE_FIN_WAIT2:
  case STATE_TIME_WAIT:
    switch (what) {
    case TCP_WHAT_TIMEOUT:
      if (tcb->tcpstate == STATE_TIME_WAIT) {
        tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
        return 1;
      }
      break;
    case TCP_WHAT_ACK:
      tcb->tcpstate = STATE_TIME_WAIT;
      LOGSEND(tcb, "+timeout");
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV((uint64_t)secs + 1, usecs));
      break;
    case TCP_WHAT_FIN:
      tcb->seqno_them = seqno_them + 1;
      LOGSEND(tcb, "peer(ACK) [acknowledge FIN] (TCP_WHAT_FIN)");
      tcpcon_send_packet(tcpcon, tcb, TH_ACK, NULL, 0, false, 0);
      tcb->tcpstate = STATE_TIME_WAIT;
      LOGSEND(tcb, "+timeout");
      timeouts_add(tcpcon->timeouts, tcb->timeout,
                   offsetof(struct TCP_Control_Block, timeout),
                   TICKS_FROM_TV((uint64_t)secs + 5, usecs));
      break;
    case TCP_WHAT_SYNACK:
    case TCP_WHAT_RST:
    case TCP_WHAT_DATA:
    case TCP_WHAT_DATA_END:
      break;
    }
    break;

  case STATE_LAST_ACK:
    LOGip(LEVEL_INFO, &tcb->ip_them, tcb->port_them,
          "=%s : %s                  \n", state_to_string(tcb->tcpstate),
          what_to_string(what));
    // LOG(LEVEL_INFO, "TCP-state: unknown state\n");
    break;
  default:
    LOG(LEVEL_INFO, "TCP-state: unknown state\n");
  }
  return 1;
}
