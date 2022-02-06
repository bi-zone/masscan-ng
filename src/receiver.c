#include <assert.h>
#include <inttypes.h>

#include "logger.h"
#include "main-dedup.h" /* ignore duplicate responses */
#include "main-globals.h"
#include "main-params.h"
#include "main-ptrace.h"    /* for nmap --packet-trace feature */
#include "masscan-status.h" /* open or closed */
#include "masscan.h"
#include "misc-rstfilter.h"
#include "output.h"       /* for outputting results */
#include "pixie-timer.h"  /* portable time functions */
#include "proto-arp.h"    /* for responding to ARP requests */
#include "proto-icmp.h"   /* handle ICMP responses */
#include "proto-oproto.h" /* Other protocols on top of IP */
#include "proto-sctp.h"
#include "proto-tcp.h" /* for TCP/IP connection table */
#include "proto-udp.h" /* handle UDP responses */
#include "rawsock-adapter.h"
#include "rawsock-pcapfile.h" /* for saving pcap files w/ raw packets */
#include "rawsock.h"          /* API on top of Linux, Windows, Mac OS X*/
#include "stack-arpv4.h"
#include "stack-ndpv6.h"
#include "syn-cookie.h" /* for SYN-cookies on send */

static void handle_packet(struct ThreadPair *parms, struct Output *out,
                          struct DedupTable *dedup,
                          struct DedupTable *echo_reply_dedup,
                          struct ResetFilter *rf,
                          struct TCP_ConnectionTable *tcpcon,
                          struct UDP_ConnectionTable *udpcon,
                          struct PacketBufferRecv *p_recv);

static unsigned is_nic_port(const struct Masscan *masscan, unsigned port) {
  size_t i;
  for (i = 0; i < masscan->nic_count; i++) {
    if (is_my_port(&masscan->nic[i].src, port)) {
      return 1;
    }
  }
  return 0;
}

static unsigned is_ipv6_multicast(const ipaddress *ip_me) {
  /* If this is an IPv6 multicast packet, one sent to the IPv6
   * address with a prefix of FF02::/16 */
  return ip_me->version == 6 && (ip_me->ipv6.hi >> 48ULL) == 0xFF02;
}

static void receive_read_thread(void *v) {
  struct ThreadPair *parms = (struct ThreadPair *)v;
  struct Adapter *adapter = parms->adapter;

  pixie_set_thread_name("recv_read");

  while (!is_rx_done) {
    unsigned length;
    unsigned secs;
    unsigned usecs;
    const unsigned char *px;
    int err;
    struct PacketBufferRecv *response = NULL;
    uint64_t wait = 100;

    err = rawsock_recv_packet(adapter, &length, &secs, &usecs, &px);
    if (err != 0) {
      continue;
    }

    if (length > ETH_FRAME_LEN) {
      continue;
    }

    for (err = 1; err;) {
      err = rte_ring_sc_dequeue(parms->stack->recv_packet_buffers,
                                (void **)&response);
      if (err != 0) {
        static int is_warning_printed = 0;
        if (!is_warning_printed) {
          LOG(LEVEL_WARNING, "packet buffers recv empty (reduce rate)\n");
          is_warning_printed = 1;
        }
        pixie_usleep(wait = (uint64_t)(wait * 1.5)); /* no packet available */
      }
    }

    if (response == NULL) {
      LOG(LEVEL_WARNING, "Can't get response from packet_buffers_recv\n");
      return;
    }

    response->length = length;
    response->secs = secs;
    response->usecs = usecs;
    memcpy(response->px, px, length);
    parms->secs_last_recv = secs;
    parms->usecs_last_recv = usecs;

    for (err = 1; err;) {
      err = rte_ring_sp_enqueue(parms->stack->recv_queue, response);
      if (err != 0) {
        LOG(LEVEL_WARNING, "recv queue full (should be impossible)\n");
        pixie_usleep(100); /* no space available */
      }
    }
  }
}

struct ThreadSchedulerRecv {
  size_t thread;
  struct PcapFile *pcapfile;
  struct ThreadPair *thread_pair;
};

static void receive_scheduler_thread(void *v) {
  struct ThreadSchedulerRecv *thread_scheduler_recv =
      (struct ThreadSchedulerRecv *)v;
  struct ThreadPair *parms = thread_scheduler_recv->thread_pair;
  struct Adapter *adapter = parms->adapter;
  int data_link = stack_if_datalink(adapter);
  struct stack_t *stack = parms->stack;
  uint64_t timeout;

  pixie_set_thread_name("recv_sched");

  timeout = 0;
  while (!is_rx_done) {
    int err;
    int res;
    size_t recv_thread_index;
    struct PacketBufferRecv *p_recv;

    /* RECEIVE */
    err = rte_ring_sc_dequeue(stack->recv_queue, (void **)&p_recv);
    if (err) {
      if (timeout > 900000) {
        LOG(LEVEL_WARNING, "[receive_scheduler_thread]tcpcon_timeouts\r\r\n");
        timeout = 0;
      }
      pixie_usleep(100);
      timeout += 100;
      continue; /* queue is empty, nothing to parse */
    }
    timeout = 0;

    parms->secs_current_recv = p_recv->secs;
    parms->usecs_current_recv = p_recv->usecs;

    /* Save raw packet in --pcap file */
    if (thread_scheduler_recv->pcapfile) {
      if (p_recv->length <= (size_t)UINT_MAX) {
        unsigned length = (unsigned)p_recv->length;
        pcapfile_writeframe(thread_scheduler_recv->pcapfile, p_recv->px, length,
                            length, p_recv->secs, p_recv->usecs);
      } else {
        LOG(LEVEL_WARNING, "Packet size too large to write to pcapfile\n");
      }
    }

    /* "Preprocess" the response packet. This means to go through and
     * figure out where the TCP/IP headers are and the locations of
     * some fields, like IP address and port numbers. */
    res = preprocess_frame(p_recv->px, p_recv->length, data_link,
                           &p_recv->parsed);
    if (!res) {
      for (err = 1; err;) {
        err = rte_ring_mp_enqueue(stack->recv_packet_buffers, p_recv);
        if (err) {
          LOG(LEVEL_WARNING, "recv queue full (should be impossible)\n");
          pixie_usleep(100);
        }
      }
      continue; /* corrupt packet */
    }

    if (stack->recv_thread_count <= 1) {
      recv_thread_index = 0;
    } else {
      unsigned hash;
      if (p_recv->parsed.dst_ip.version == 6) {
        hash = (unsigned)(p_recv->parsed.dst_ip.ipv6.lo ^
                          p_recv->parsed.dst_ip.ipv6.hi ^
                          p_recv->parsed.src_ip.ipv6.lo ^
                          p_recv->parsed.src_ip.ipv6.hi);
      } else {
        hash = p_recv->parsed.dst_ip.ipv4 ^ p_recv->parsed.src_ip.ipv4;
      }
      recv_thread_index = (size_t)hash % stack->recv_thread_count;
    }

    /*{
            size_t i_th;
            size_t min_queue_count, tmp_queue_count;
            recv_thread_index = 0;
            min_queue_count =
    (size_t)rte_ring_count(stack->recv_thread[0].recv_th_queue); for(i_th = 1;
    i_th < stack->recv_thread_count; i_th++) { tmp_queue_count =
    (size_t)rte_ring_count(stack->recv_thread[i_th].recv_th_queue);
                    if(tmp_queue_count < min_queue_count) {
                            min_queue_count = tmp_queue_count;
                            recv_thread_index = i_th;
                    }
            }
    }*/

    for (err = 1; err;) {
      err = rte_ring_sp_enqueue(
          stack->recv_thread[recv_thread_index].recv_th_queue, p_recv);
      if (err) {
        LOG(LEVEL_WARNING,
            "recv thread%[" PRIuPTR "] queue full (should be impossible)\n",
            recv_thread_index);
        pixie_usleep(100);
      }
    }
  }
}

struct ThreadHandleRecv {
  size_t index;
  size_t thread;
  struct Output *out;
  struct DedupTable *dedup;
  struct DedupTable *echo_reply_dedup;
  struct ResetFilter *rf;
  struct TCP_ConnectionTable *tcpcon;
  struct UDP_ConnectionTable *udpcon;
  PACKET_QUEUE *recv_th_queue;
  struct ThreadPair *thread_pair;
};

void receive_handle_thread(void *v) {
  struct ThreadHandleRecv *thread_handle_recv = (struct ThreadHandleRecv *)v;
  struct ThreadPair *thread_pair_params = thread_handle_recv->thread_pair;
  struct stack_t *stack = thread_pair_params->stack;
  char thread_name[128];
  uint64_t timeout;

  snprintf(thread_name, ARRAY_SIZE(thread_name), "[%" PRIuPTR "]recv_hdl",
           thread_handle_recv->index);
  pixie_set_thread_name(thread_name);

  timeout = 0;
  while (!is_rx_done) {
    int err;
    struct PacketBufferRecv *p_recv;

    /* RECEIVE */
    err = rte_ring_sc_dequeue(thread_handle_recv->recv_th_queue,
                              (void **)&p_recv);
    if (err) {
      if (timeout > 900000) {
        if (thread_handle_recv->tcpcon) {
          tcpcon_timeouts(thread_handle_recv->tcpcon, (unsigned)time(0), 0);
        }
        LOG(LEVEL_WARNING, "[receive_handle_thread]tcpcon_timeouts\r\r\n");
        timeout = 0;
      }
      pixie_usleep(100);
      timeout += 100;
      continue; /* queue is empty, nothing to parse */
    }
    timeout = 0;

    /* Do any TCP event timeouts based on the current timestamp from
     * the packet. For example, if the connection has been open for
     * around 10 seconds, we'll close the connection. (--banners) */
    if (thread_handle_recv->tcpcon) {
      tcpcon_timeouts(thread_handle_recv->tcpcon, p_recv->secs, p_recv->usecs);
    }

    handle_packet(
        thread_pair_params, thread_handle_recv->out, thread_handle_recv->dedup,
        thread_handle_recv->echo_reply_dedup, thread_handle_recv->rf,
        thread_handle_recv->tcpcon, thread_handle_recv->udpcon, p_recv);

    for (err = 1; err;) {
      err = rte_ring_mp_enqueue(stack->recv_packet_buffers, p_recv);
      if (err) {
        LOG(LEVEL_WARNING, "recv queue full (should be impossible)\n");
        pixie_usleep(100);
      }
    }
  }
}

static void handle_packet(struct ThreadPair *parms, struct Output *out,
                          struct DedupTable *dedup,
                          struct DedupTable *echo_reply_dedup,
                          struct ResetFilter *rf,
                          struct TCP_ConnectionTable *tcpcon,
                          struct UDP_ConnectionTable *udpcon,
                          struct PacketBufferRecv *p_recv) {

  int status;
  const struct Masscan *masscan = parms->masscan;
  uint64_t entropy = masscan->seed;
  ipaddress ip_me = p_recv->parsed.dst_ip;
  unsigned port_me = p_recv->parsed.port_dst;
  ipaddress ip_them = p_recv->parsed.src_ip;
  unsigned port_them = p_recv->parsed.port_src;
  unsigned seqno_me = TCP_ACKNO(p_recv->px, p_recv->parsed.transport_offset);
  unsigned seqno_them = TCP_SEQNO(p_recv->px, p_recv->parsed.transport_offset);
  unsigned cookie;
  struct TCP_Control_Block *tcb = NULL;
  unsigned Q = 0;

  assert(ip_me.version != 0);
  assert(ip_them.version != 0);

  switch (p_recv->parsed.ip_protocol) {
  case 132: /* SCTP */
    cookie = syn_cookie(&ip_them, port_them | (Proto_SCTP << 16), &ip_me,
                        port_me, entropy) &
             0xFFFFFFFF;
    break;
  default:
    cookie =
        syn_cookie(&ip_them, port_them, &ip_me, port_me, entropy) & 0xFFFFFFFF;
  }

  /* verify: my IP address */
  if (!is_my_ip(parms->stack->src, &ip_me)) {
    /* NDP Neighbor Solicitations don't come to our IP address, but to
     * a multicast address */
    if (is_ipv6_multicast(&ip_me)) {
      if (p_recv->parsed.found == FOUND_NDPv6 && p_recv->parsed.opcode == 135) {
        stack_ndpv6_incoming_request(parms->stack, &p_recv->parsed, p_recv->px,
                                     p_recv->length);
      }
    }
    return;
  }

  /* Handle non-TCP protocols */
  switch (p_recv->parsed.found) {
  case FOUND_NDPv6:
    switch (p_recv->parsed.opcode) {
    case 133: /* Router Solicitation */
      /* Ignore router solicitations, since we aren't a router */
      return;
    case 134: /* Router advertisement */
      /* TODO: We need to process router advertisements while scanning
       * so that we can print warning messages if router information
       * changes while scanning. */
      return;
    case 135: /* Neighbor Solicitation */
      /* When responses come back from our scans, the router will send us
       * these packets. We need to respond to them, so that the router
       * can then forward the packets to us. If we don't respond, we'll
       * get no responses. */
      stack_ndpv6_incoming_request(parms->stack, &p_recv->parsed, p_recv->px,
                                   p_recv->length);
      return;
    case 136: /* Neighbor Advertisement */
      /* TODO: If doing an --ndpscan, the scanner subsystem needs to deal
       * with these */
      return;
    case 137: /* Redirect */
      /* We ignore these, since we really don't have the capability to send
       * packets to one router for some destinations and to another router
       * for other destinations */
      return;
    default:
      break;
    }
    return;
  case FOUND_ARP:
    LOGip(LEVEL_DEBUG, &ip_them, 0, "-> ARP [%u] \n",
          p_recv->px[p_recv->parsed.found_offset]);
    switch (p_recv->parsed.opcode) {
    case 1: /* request */
      /* This function will transmit a "reply" to somebody's ARP request
       * for our IP address (as part of our user-mode TCP/IP).
       * Since we completely bypass the TCP/IP stack, we  have to handle ARPs
       * ourself, or the router will lose track of us.*/
      stack_arp_incoming_request(parms->stack, &ip_me.ipv4, &parms->source_mac,
                                 p_recv->px, p_recv->length);
      break;
    case 2: /* response */
      /* This is for "arp scan" mode, where we are ARPing targets rather
       * than port scanning them */

      /* If we aren't doing an ARP scan, then ignore ARP responses */
      if (!masscan->scan_type.arp)
        break;

      /* If this response isn't in our range, then ignore it */
      if (!rangelist_is_contains(&masscan->targets.ipv4, &ip_them.ipv4)) {
        break;
      }

      /* Ignore duplicates */
      if (dedup_is_duplicate(dedup, &ip_them, 0, &ip_me, 0)) {
        return;
      }

      /* ...everything good, so now report this response */
      arp_recv_response(out, p_recv->secs, p_recv->px, p_recv->length,
                        &p_recv->parsed);
      break;
    }
    return;
  case FOUND_UDP:
  case FOUND_DNS:
    if (!is_nic_port(masscan, port_me)) {
      return;
    }
    if (parms->masscan->nmap.packet_trace) {
      packet_trace(stdout, parms->pt_start, p_recv->px, p_recv->length, 0);
    }
    handle_udp(udpcon, out, p_recv->secs, p_recv->px, p_recv->length,
               &p_recv->parsed, entropy);
    return;
  case FOUND_ICMP: {
    unsigned type = p_recv->parsed.port_src;
    /* dedup ICMP echo replies as well as SYN/ACK replies */
    if ((type == 0 || type == 129) &&
        dedup_is_duplicate(echo_reply_dedup, &ip_them, 0, &ip_me, 0)) {
      return;
    }
    handle_icmp(out, p_recv->secs, p_recv->px, p_recv->length, &p_recv->parsed,
                entropy);
  }
    return;
  case FOUND_SCTP:
    handle_sctp(out, p_recv->secs, p_recv->px, p_recv->length, cookie,
                &p_recv->parsed, entropy);
    break;
  case FOUND_OPROTO: /* other IP proto */
    handle_oproto(out, p_recv->secs, p_recv->px, p_recv->length,
                  &p_recv->parsed, entropy);
    break;
  case FOUND_TCP:
    /* fall down to below */
    break;
  default:
    return;
  }

  /* verify: my port number */
  if (!is_my_port(parms->stack->src, port_me)) {
    return;
  }
  if (parms->masscan->nmap.packet_trace) {
    packet_trace(stdout, parms->pt_start, p_recv->px, p_recv->length, 0);
  }

  Q = 0;

  {
    char buf[64];
    LOGip(LEVEL_DEBUG_3, &ip_them, port_them,
          "-> TCP ackno=0x%08x flags=0x%02x(%s)\n", seqno_me,
          TCP_FLAGS(p_recv->px, p_recv->parsed.transport_offset),
          reason_string(TCP_FLAGS(p_recv->px, p_recv->parsed.transport_offset),
                        buf, sizeof(buf)));
  }

  /* If recording --banners, create a new "TCP Control Block (TCB)" */
  tcb = NULL;
  if (tcpcon) {
    /* does a TCB already exist for this connection? */
    tcb = tcb_lookup(tcpcon, &ip_me, &ip_them, port_me, port_them);

    if (TCP_IS_SYNACK(p_recv->px, p_recv->parsed.transport_offset)) {
      ipaddress_formatted_t fmt;
      ipaddress_fmt(&fmt, &ip_them);
      if (cookie != seqno_me - 1) {
        LOG(LEVEL_DEBUG, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n",
            fmt.string, seqno_me - 1, cookie);
        return;
      }

      if (tcb == NULL) {
        tcb =
            tcpcon_create_tcb(tcpcon, &ip_me, &ip_them, port_me, port_them,
                              seqno_me, seqno_them + 1, p_recv->parsed.ip_ttl);
        pixie_locked_inc_d64(&parms->total_tcbs);
      }

      Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_SYNACK, 0, 0, p_recv->secs,
                              p_recv->usecs, seqno_them + 1);

    } else if (tcb) {
      /* If this is an ACK, then handle that first */
      if (TCP_IS_ACK(p_recv->px, p_recv->parsed.transport_offset)) {
        Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_ACK, 0, seqno_me,
                                p_recv->secs, p_recv->usecs, seqno_them);
      }

      /* If this contains payload, handle that second */
      if (p_recv->parsed.app_length) {
        if (TCP_IS_FIN(p_recv->px, p_recv->parsed.transport_offset) &&
            !TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {
          Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_DATA_END,
                                  p_recv->px + p_recv->parsed.app_offset,
                                  p_recv->parsed.app_length, p_recv->secs,
                                  p_recv->usecs, seqno_them);
        } else {
          Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_DATA,
                                  p_recv->px + p_recv->parsed.app_offset,
                                  p_recv->parsed.app_length, p_recv->secs,
                                  p_recv->usecs, seqno_them);
        }
      } else {
        /* If this is a FIN, handle that. Note that ACK +
         * payload + FIN can come together */
        if (TCP_IS_FIN(p_recv->px, p_recv->parsed.transport_offset) &&
            !TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {
          Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_FIN, 0,
                                  p_recv->parsed.app_length, p_recv->secs,
                                  p_recv->usecs, seqno_them);
        }
      }

      /* If this is a RST, then we'll be closing the connection */
      if (TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {
        Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_RST, 0, 0, p_recv->secs,
                                p_recv->usecs, seqno_them);
      }
    } else if (TCP_IS_FIN(p_recv->px, p_recv->parsed.transport_offset)) {
      ipaddress_formatted_t fmt;
      ipaddress_fmt(&fmt, &ip_them);
      /* NO TCB!
       *  This happens when we've sent a FIN, deleted our connection,
       *  but the other side didn't get the packet. */
      LOG(LEVEL_DEBUG_2, "%s: received FIN but no TCB\n", fmt.string);
      if (TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {
        /* ignore if it's own TCP flag is set */
      } else {
        int is_suppress;
        is_suppress =
            rstfilter_is_filter(rf, &ip_me, port_me, &ip_them, port_them);
        if (!is_suppress) {
          tcpcon_send_RST(tcpcon, &ip_me, &ip_them, port_me, port_them,
                          seqno_them, seqno_me);
        }
      }
    }
  }

  if (Q == 0) {
    // pass
  }

  if (TCP_IS_SYNACK(p_recv->px, p_recv->parsed.transport_offset) ||
      TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {

    /* verify: syn-cookies */
    if (cookie != seqno_me - 1) {
      ipaddress_formatted_t fmt;
      ipaddress_fmt(&fmt, &ip_them);
      LOG(LEVEL_DEBUG_3, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n",
          fmt.string, seqno_me - 1, cookie);
      return;
    }

    /* verify: ignore duplicates */
    if (dedup_is_duplicate(dedup, &ip_them, port_them, &ip_me, port_me)) {
      return;
    }

    /* keep statistics on number received */
    if (TCP_IS_SYNACK(p_recv->px, p_recv->parsed.transport_offset)) {
      pixie_locked_inc_d64(&parms->total_synacks);
    }

    /* figure out the status */
    status = PortStatus_Unknown;
    if (TCP_IS_SYNACK(p_recv->px, p_recv->parsed.transport_offset))
      status = PortStatus_Open;
    if (TCP_IS_RST(p_recv->px, p_recv->parsed.transport_offset)) {
      status = PortStatus_Closed;
    }
    /* This is where we do the output */
    if (tcpcon == NULL || tcb == NULL) {
      output_report_status(
          out, global_now, status, &ip_them, 6, /* ip proto = tcp */
          port_them,
          p_recv->px[p_recv->parsed.transport_offset + 13], /* tcp flags */
          p_recv->parsed.ip_ttl, p_recv->parsed.mac_src);
    } else {
      assert(status != 0);
      statout_new_status(&(tcb->statout), global_now, status,
                         p_recv->px[p_recv->parsed.transport_offset + 13],
                         p_recv->parsed.ip_ttl, p_recv->parsed.mac_src);
    }

    /* Send RST so other side isn't left hanging (only doing this in
     * complete stateless mode where we aren't tracking banners) */
    if (tcpcon == NULL && !masscan->is_noreset) {
      tcp_send_RST(&parms->tmplset->pkts[Proto_TCP], parms->stack, &ip_them,
                   &ip_me, port_them, port_me, 0, seqno_me);
    }
  }
}

/***************************************************************************
 *
 * Asynchronous receive thread
 *
 * The transmit and receive threads run independently of each other. There
 * is no record what was transmitted. Instead, the transmit thread sets a
 * "SYN-cookie" in transmitted packets, which the receive thread will then
 * use to match up requests with responses.
 ***************************************************************************/
void receive_thread(void *v) {

  struct ThreadPair *parms = (struct ThreadPair *)v;
  const struct Masscan *masscan = parms->masscan;
  size_t thread_read_recv;
  struct ThreadHandleRecv threads_handle_recv[MAX_THREAD_HANDLE_RECV_COUNT] = {
      {0}};
  struct ThreadSchedulerRecv thread_scheduler_recv = {0};
  struct stack_t *stack = parms->stack;
  size_t iter_recv_handle_thread;

  /* some status variables */
  parms->total_synacks = 0;
  parms->total_tcbs = 0;

  pixie_set_thread_name("recv");

  LOG(LEVEL_INFO, "[+] starting receive thread #%" PRIuPTR "\n",
      parms->nic_index);

  /* If configured, open a --pcap file for saving raw packets. This is
   * so that we can debug scans, but also so that we can look at the
   * strange things people send us. Note that we don't record transmitted
   * packets, just the packets we've received. */
  if (masscan->pcap_filename[0]) {
    thread_scheduler_recv.pcapfile =
        pcapfile_openwrite(masscan->pcap_filename, 1);
  }
  thread_scheduler_recv.thread_pair = parms;

  for (iter_recv_handle_thread = 0;
       iter_recv_handle_thread < masscan->recv_handle_thread_count;
       iter_recv_handle_thread++) {

    threads_handle_recv[iter_recv_handle_thread].index =
        iter_recv_handle_thread;
    /* Open output. This is where results are reported when saving
     * the --output-format to the --output-filename */
    struct Output *out;
    out = output_create(masscan, parms->nic_index, iter_recv_handle_thread);
    threads_handle_recv[iter_recv_handle_thread].out = out;
    threads_handle_recv[iter_recv_handle_thread].thread_pair = parms;

    threads_handle_recv[iter_recv_handle_thread].recv_th_queue =
        stack->recv_thread[iter_recv_handle_thread].recv_th_queue;
    /* Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one. */
    threads_handle_recv[iter_recv_handle_thread].dedup = dedup_create();
    threads_handle_recv[iter_recv_handle_thread].echo_reply_dedup =
        dedup_create();
    /* For reducing RST responses, see rstfilter_is_filter() below */
    threads_handle_recv[iter_recv_handle_thread].rf =
        rstfilter_create(masscan->seed, 16384);
    /* Create a TCP connection table (per thread pair) for interacting with live
     * connections when doing --banners */
    if (masscan->is_banners) {
      struct TcpCfgPayloads *pay;
      size_t iter_http_param;

      /* Create TCP connection table */
      threads_handle_recv[iter_recv_handle_thread].tcpcon = tcpcon_create_table(
          ((size_t)(masscan->max_rate / 5.) / masscan->nic_count), stack,
          &parms->tmplset->pkts[Proto_TCP], output_report_sign,
          output_report_status, output_report_banner, output_ssl_key, out,
          masscan->tcb.timeout, masscan->seed);

      /* Create UDP connection table */
      threads_handle_recv[iter_recv_handle_thread].udpcon =
          udpcon_create_table();

      /* Set some flags [kludge] */
      tcpcon_set_banner_flags(
          threads_handle_recv[iter_recv_handle_thread].tcpcon,
          (bool)masscan->is_capture_cert, (bool)masscan->is_capture_servername,
          (bool)masscan->is_ssl_dynamic,
          (bool)masscan->output.filename_ssl_keys[0],
          (bool)masscan->is_capture_html, (bool)masscan->is_capture_heartbleed,
          (bool)masscan->is_capture_ticketbleed,
          (bool)masscan->is_dynamic_set_host);

      tcpcon_init_banner1(threads_handle_recv[iter_recv_handle_thread].tcpcon);
      udpcon_init_banner1(threads_handle_recv[iter_recv_handle_thread].udpcon);

      /* Initialize TCP scripting */
      scripting_init_tcp(threads_handle_recv[iter_recv_handle_thread].tcpcon,
                         masscan->scripting.L);

      if (masscan->regex) {
        tcpcon_set_regexp(threads_handle_recv[iter_recv_handle_thread].tcpcon,
                          masscan->regex, masscan->regex_extra,
                          masscan->is_regex_only_banners);
      }

      if (masscan->is_hello_smbv1) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "hello", 5,
            "smbv1");
      }
      if (masscan->is_hello_http) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "hello", 4,
            "http");
      }
      if (masscan->is_hello_ssl) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "hello", 3,
            "ssl");
      }
      if (masscan->is_heartbleed) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "heartbleed",
            1, "1");
      }
      if (masscan->is_ticketbleed) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "ticketbleed",
            1, "1");
      }
      if (masscan->is_poodle_sslv3) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "sslv3", 1,
            "1");
      }

      if (masscan->http.payload) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "http-payload",
            masscan->http.payload_length, masscan->http.payload);
      }

      if (masscan->http.user_agent) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon,
            "http-user-agent", masscan->http.user_agent_length,
            masscan->http.user_agent);
      }

      if (masscan->http.host) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "http-host",
            masscan->http.host_length, masscan->http.host);
      }

      if (masscan->http.method) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "http-method",
            masscan->http.method_length, masscan->http.method);
      }

      if (masscan->http.url) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "http-url",
            masscan->http.url_length, masscan->http.url);
      }

      if (masscan->http.version) {
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "http-version",
            masscan->http.version_length, masscan->http.version);
      }

      if (masscan->tcp_connection_timeout) {
        char foo[64];
        sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "timeout",
            strlen(foo), foo);
      }

      if (masscan->tcp_hello_timeout) {
        char foo[64];
        sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_hello_timeout);
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon,
            "hello-timeout", strlen(foo), foo);
      }

      for (iter_http_param = 0; iter_http_param < masscan->http.headers_count;
           iter_http_param++) {
        tcpcon_set_http_header(
            threads_handle_recv[iter_recv_handle_thread].tcpcon,
            masscan->http.headers[iter_http_param].name,
            masscan->http.headers[iter_http_param].value_length,
            masscan->http.headers[iter_http_param].value, http_field_replace);
      }

      for (iter_http_param = 0; iter_http_param < masscan->http.cookies_count;
           iter_http_param++) {
        tcpcon_set_http_header(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, "Cookie",
            masscan->http.cookies[iter_http_param].value_length,
            masscan->http.cookies[iter_http_param].value, http_field_add);
      }

      for (iter_http_param = 0; iter_http_param < masscan->http.remove_count;
           iter_http_param++) {
        tcpcon_set_http_header(
            threads_handle_recv[iter_recv_handle_thread].tcpcon,
            masscan->http.headers[iter_http_param].name, 0, NULL,
            http_field_remove);
      }

      for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
        char name[64];
        sprintf_s(name, sizeof(name), "hello-string[%u]", pay->port);
        tcpcon_set_parameter(
            threads_handle_recv[iter_recv_handle_thread].tcpcon, name,
            strlen(pay->payload_base64), pay->payload_base64);
      }
    }
  }

  /* In "offline" mode, we don't have any receive threads, so simply
   * wait until transmitter thread is done then go to the end */
  if (masscan->is_offline) {
    while (!is_rx_done) {
      pixie_usleep(10000);
    }
    parms->done_receiving = 1;
    goto end;
  }

  /* Receive packets. This is where we catch any responses and print
   * them to the terminal. */
  LOG(LEVEL_WARNING,
      "[+] THREAD: recv: starting main loop. "
      "Count handle threads %" PRIuPTR ".\n",
      masscan->recv_handle_thread_count);
  for (iter_recv_handle_thread = 0;
       iter_recv_handle_thread < masscan->recv_handle_thread_count;
       iter_recv_handle_thread++) {
    threads_handle_recv[iter_recv_handle_thread].thread =
        pixie_begin_thread(receive_handle_thread, 0,
                           &threads_handle_recv[iter_recv_handle_thread]);
  }
  thread_scheduler_recv.thread =
      pixie_begin_thread(receive_scheduler_thread, 0, &thread_scheduler_recv);
  thread_read_recv = pixie_begin_thread(receive_read_thread, 0, parms);
  pixie_wait_barrier(parms->barrier_main_loop);

  LOG(LEVEL_WARNING, "[+] wait recv threads\n");
  pixie_thread_join(thread_read_recv);
  pixie_thread_join(thread_scheduler_recv.thread);
  for (iter_recv_handle_thread = 0;
       iter_recv_handle_thread < masscan->recv_handle_thread_count;
       iter_recv_handle_thread++) {
    pixie_thread_join(threads_handle_recv[iter_recv_handle_thread].thread);
  }

  LOG(LEVEL_INFO, "[+] exiting receive thread #%" PRIuPTR "\n",
      parms->nic_index);

  /* cleanup */
end:
  for (iter_recv_handle_thread = 0;
       iter_recv_handle_thread < masscan->recv_handle_thread_count;
       iter_recv_handle_thread++) {

    if (threads_handle_recv[iter_recv_handle_thread].tcpcon) {
      tcpcon_destroy_table(threads_handle_recv[iter_recv_handle_thread].tcpcon);
    }
    if (threads_handle_recv[iter_recv_handle_thread].udpcon) {
      udpcon_destroy_table(threads_handle_recv[iter_recv_handle_thread].udpcon);
    }
    dedup_destroy(
        threads_handle_recv[iter_recv_handle_thread].echo_reply_dedup);
    dedup_destroy(threads_handle_recv[iter_recv_handle_thread].dedup);
    rstfilter_destroy(threads_handle_recv[iter_recv_handle_thread].rf);
    output_destroy(threads_handle_recv[iter_recv_handle_thread].out);
  }

  if (thread_scheduler_recv.pcapfile) {
    pcapfile_close(thread_scheduler_recv.pcapfile);
  }

  /* Thread is about to exit */
  parms->done_receiving = 1;
}
