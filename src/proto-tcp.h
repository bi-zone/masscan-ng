#ifndef PROTO_TCP_H
#define PROTO_TCP_H

#include <pcre.h>

#include "event-timeout.h" /* for tracking future events */
#include "main-params.h"
#include "massip-addr.h"
#include "output.h"
#include "proto-banner1.h"
#include "proto-banout.h"
#include "proto-signout.h"
#include "proto-statout.h"
#include "stack-queue.h"

struct Adapter;

struct ResendPayload {
  /* If the payload we've sent was dynamically allocated with
   * malloc() from the heap, in which case we'll have to free()
   * it. (Most payloads are static memory) */
  unsigned is_dynamic : 1;
  unsigned char *data;
  unsigned short data_length;
};

/***************************************************************************
 * A "TCP control block" is what most operating-systems/network-stack
 * calls the structure that corresponds to a TCP connection. It contains
 * things like the IP addresses, port numbers, sequence numbers, timers,
 * and other things.
 ***************************************************************************/
struct TCP_Control_Block {

  ipaddress ip_me;
  ipaddress ip_them;

  unsigned short port_me;
  unsigned short port_them;

  uint32_t seqno_me;   /* next seqno I will use for transmit */
  uint32_t seqno_them; /* the next seqno I expect to receive */
  uint32_t ackno_me;
  uint32_t ackno_them;
  uint32_t seqno_them_first; /* ipv6-todo */

  struct TCP_Control_Block *next;
  struct TimeoutEntry timeout[1];

  unsigned char ttl;
  unsigned tcpstate : 4;
  unsigned is_ipv6 : 1;

  /** Set to true when the TCB is in-use/allocated, set to zero
   * when it's about to be deleted soon */
  unsigned is_active : 1;

  unsigned established;

  time_t when_created;

  struct ResendPayload payload;
  /* If Running a script, the thread object */
  struct ScriptingThread *scripting_thread;

  struct BannerOutput banout;
  struct StatusOutput statout;
  struct SignOutput signout;
  struct KeyOutput *keyout;

  struct ProtocolState banner1_state;

  unsigned packet_number;
};

struct TemplatePacket;
struct TCP_ConnectionTable;
struct lua_State;

#define TCP_SEQNO(px, i)                                                       \
  ((unsigned)px[(i) + 4] << 24 | (unsigned)px[(i) + 5] << 16 |                 \
   (unsigned)px[(i) + 6] << 8 | (unsigned)px[(i) + 7])
#define TCP_ACKNO(px, i)                                                       \
  ((unsigned)px[(i) + 8] << 24 | (unsigned)px[(i) + 9] << 16 |                 \
   (unsigned)px[(i) + 10] << 8 | (unsigned)px[(i) + 11])
#define TCP_FLAGS(px, i) (px[(i) + 13])
#define TCP_IS_SYNACK(px, i) ((TCP_FLAGS(px, i) & 0x12) == 0x12)
#define TCP_IS_ACK(px, i) ((TCP_FLAGS(px, i) & 0x10) == 0x10)
#define TCP_IS_RST(px, i) ((TCP_FLAGS(px, i) & 0x4) == 0x4)
#define TCP_IS_FIN(px, i) ((TCP_FLAGS(px, i) & 0x1) == 0x1)

/* [KLUDGE] The 'tcpcon' module doesn't have access to the main configuration,
 * so specific configuration options have to be sent to it using this
 * function. */

enum http_field_t {
  http_field_replace,
  http_field_add,
  http_field_remove,
  http_field_method,
  http_field_url,
  http_field_version,
};

enum http_request_line_t {
  http_request_line_method,
  http_request_line_url,
  http_request_line_version,
  http_request_line_payload,
};

void tcpcon_set_parameter(struct TCP_ConnectionTable *tcpcon, const char *name,
                          size_t value_length, const void *value);
void tcpcon_set_http_header(struct TCP_ConnectionTable *tcpcon,
                            const char *name, size_t value_length,
                            const void *value, enum http_field_t what);
void tcpcon_set_banner_flags(struct TCP_ConnectionTable *tcpcon,
                             bool is_capture_cert, bool is_capture_servername,
                             bool is_ssl_dynamic, bool is_capture_key,
                             bool is_capture_html, bool is_capture_heartbleed,
                             bool is_capture_ticketbleed, bool is_set_host);
void tcpcon_set_regexp(struct TCP_ConnectionTable *tcpcon, pcre *re,
                       pcre_extra *re_extra, unsigned is_regex_only_banners);

void scripting_init_tcp(struct TCP_ConnectionTable *tcpcon,
                        struct lua_State *L);
void tcpcon_init_banner1(struct TCP_ConnectionTable *tcpcon);

/**
 * Create a TCP connection table (to store TCP control blocks) with
 * the desired initial size.
 *
 * @param entry_count
 *      A hint about the desired initial size. This should be about twice
 *      the number of outstanding connections, so you should base this number
 *      on your transmit rate (the faster the transmit rate, the more
 *      outstanding connections you'll have). This function will automatically
 *      round this number up to the nearest power of 2, or round it down
 *      if it causes malloc() to not be able to allocate enough memory.
 * @param entropy
 *      Seed for syn-cookie randomization
 */
struct TCP_ConnectionTable *
tcpcon_create_table(size_t entry_count, struct stack_t *stack,
                    struct TemplatePacket *pkt_template,
                    OUTPUT_REPORT_SIGN report_sign,
                    OUTPUT_REPORT_STATUS report_status,
                    OUTPUT_REPORT_BANNER report_banner, OUTPUT_SSL_KEY ssl_key,
                    struct Output *out, time_t timeout, uint64_t entropy);

/**
 * Gracefully destroy a TCP connection table. This is the last chance for any
 * partial banners (like HTTP server version) to be sent to the output. At the
 * end of a scan, you'll see a bunch of banners all at once due to this call.
 *
 * @param tcpcon
 *      A TCP connection table created with a matching call to
 *      'tcpcon_create_table()'.
 */
void tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon);

void tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs,
                     unsigned usecs);

enum TCP_What {
  TCP_WHAT_TIMEOUT,
  TCP_WHAT_SYNACK,
  TCP_WHAT_RST,
  TCP_WHAT_FIN,
  TCP_WHAT_ACK,
  TCP_WHAT_DATA,
  TCP_WHAT_DATA_END
};

int stack_incoming_tcp(struct TCP_ConnectionTable *tcpcon,
                       struct TCP_Control_Block *entry, int what, const void *p,
                       size_t length, unsigned secs, unsigned usecs,
                       unsigned seqno_them);

/**
 * Lookup a connection record based on IP/ports.
 */
struct TCP_Control_Block *tcb_lookup(struct TCP_ConnectionTable *tcpcon,
                                     const ipaddress *ip_src,
                                     const ipaddress *ip_dst, unsigned port_src,
                                     unsigned port_dst);

/**
 * Create a new TCB (TCP control block)
 */
struct TCP_Control_Block *
tcpcon_create_tcb(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_src,
                  const ipaddress *ip_dst, unsigned port_src, unsigned port_dst,
                  unsigned my_seqno, unsigned their_seqno, unsigned ttl);

/* Acknowledge a FIN even if we've forgotten about the connection */
void tcpcon_send_FIN(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_me,
                     const ipaddress *ip_them, unsigned port_me,
                     unsigned port_them, uint32_t seqno_them,
                     uint32_t ackno_them);
void tcpcon_send_RST(struct TCP_ConnectionTable *tcpcon, const ipaddress *ip_me,
                     const ipaddress *ip_them, unsigned port_me,
                     unsigned port_them, uint32_t seqno_them,
                     uint32_t ackno_them);

/* Send a reset packet back, even if we don't have a TCP connection table */
void tcp_send_RST(struct TemplatePacket *templ, struct stack_t *stack,
                  const ipaddress *ip_them, const ipaddress *ip_me,
                  unsigned port_them, unsigned port_me, unsigned seqno_them,
                  unsigned seqno_me);

void init_application_proto(const struct Banner1 *banner1,
                            struct ProtocolState *pstate,
                            struct ResendPayload *resend_payload,
                            struct BannerOutput *banout,
                            struct KeyOutput **keyout);

void cleanup_application_proto(const struct Banner1 *banner1,
                               struct ProtocolState *pstate,
                               struct ResendPayload *resend_payload);

void switch_application_proto(
    const struct Banner1 *banner1, struct ProtocolState *pstate,
    struct ResendPayload *resend_payload, struct BannerOutput *banout,
    struct KeyOutput **keyout, unsigned short new_proto,
    const struct ProtocolParserStream *new_parser_stream);

void application_receive_hello(const struct Banner1 *banner1,
                               struct ProtocolState *tcb_state,
                               struct ResendPayload *resend_payload,
                               struct BannerOutput *banout,
                               struct KeyOutput **keyout,
                               struct InteractiveData *more);

void application_receive_next(
    const struct Banner1 *banner1, struct ProtocolState *main_tcb_state,
    struct ProtocolState *tcb_state, struct ResendPayload *resend_payload,
    const void *payload, size_t payload_length, struct BannerOutput *banout,
    struct SignOutput *signout, struct KeyOutput **keyout,
    struct InteractiveData *more);

#endif
