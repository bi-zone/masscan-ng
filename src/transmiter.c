#include "logger.h"
#include "main-globals.h"
#include "main-params.h"
#include "main-status.h" /* printf() regular status updates */
#include "masscan.h"
#include "pixie-timer.h"    /* portable time functions */
#include "rand-blackrock.h" /* the BlackRock shuffling func */
#include "rawsock.h"        /* API on top of Linux, Windows, Mac OS X*/
#include "stack-queue.h"
#include "syn-cookie.h" /* for SYN-cookies on send */
#include "util-test.h"

/***************************************************************************
 * We support a range of source IP/port. This function converts that
 * range into useful variables we can use to pick things form that range.
 ***************************************************************************/
static void adapter_get_source_addresses(
    const struct Masscan *masscan, size_t nic_index, ipv4address_t *src_ipv4,
    ipv4address_t *src_ipv4_mask, unsigned *src_port, unsigned *src_port_mask,
    ipv6address_t *src_ipv6, ipv6address_t *src_ipv6_mask) {

  const struct stack_src_t *src = &masscan->nic[nic_index].src;
  static ipv6address_t mask = {~0ULL, ~0ULL};

  *src_ipv4 = src->ipv4.first;
  *src_ipv4_mask = src->ipv4.last - src->ipv4.first;

  *src_port = src->port.first;
  *src_port_mask = src->port.last - src->port.first;

  *src_ipv6 = src->ipv6.first;

  /* TODO: currently supports only a single address. This needs to
   * be fixed to support a list of addresses */
  *src_ipv6_mask = mask;
}

#define LIMIT_RECV_QUEUE 5.0
#define LIMIT_RECV_LAG 500.0 // 0.5 ms
#define MULTI_LIMIT_RATE_FIX 400
#define LIMIT_RECV_QUEUE_RATE_FIX                                              \
  ((unsigned)LIMIT_RECV_QUEUE * MULTI_LIMIT_RATE_FIX)
#define LIMIT_RECV_LAG_RATE_FIX (LIMIT_RECV_LAG * MULTI_LIMIT_RATE_FIX)

static int64_t rate_adjustment(struct ThreadPair *parms, int64_t batch_size,
                               int64_t left_batch, bool *p_need_fix_rate) {
  struct Throttler *throttler = parms->throttler;
  int64_t batch_size_with_fix_rate;
  size_t count_recv_queue;
  double t_lag;

  count_recv_queue = stack_recv_queue_count(parms->stack);
  if (parms->secs_current_recv == 0 && parms->usecs_current_recv == 0) {
    t_lag = 0;
  } else {
    t_lag = (parms->usecs_last_recv + parms->secs_last_recv * 1000000.0) -
            (parms->usecs_current_recv + parms->secs_current_recv * 1000000.0);
  }

  if (*p_need_fix_rate == false &&
      ((count_recv_queue > LIMIT_RECV_QUEUE_RATE_FIX) ||
       (t_lag > LIMIT_RECV_LAG_RATE_FIX))) { // 200 ms
    *p_need_fix_rate = true;
    LOG(LEVEL_DEBUG,
        "Need rate decrease. Current max rate: %.2f\n%u-recv_queue, "
        "%0.2f-t_recv" STATUS_EMPTY_STRING "\n",
        throttler->max_rate, count_recv_queue, t_lag);
  }
  batch_size_with_fix_rate =
      (uint64_t)(batch_size *
                 max(0.0, min((1.0 - count_recv_queue / LIMIT_RECV_QUEUE),
                              (1. - t_lag / LIMIT_RECV_LAG))));
  left_batch = max(batch_size_with_fix_rate - (batch_size - left_batch), 0);
  if (*p_need_fix_rate && left_batch != 0) {
    throttler->max_rate = (throttler->max_rate * 0.7);
    *p_need_fix_rate = false;
    LOG(LEVEL_WARNING,
        "Rate decrease. Current max rate: %.2f" STATUS_EMPTY_STRING "\n",
        throttler->max_rate);
  }
  return left_batch;
}

/***************************************************************************
 * This thread spews packets as fast as it can
 *
 *      THIS IS WHERE ALL THE EXCITEMENT HAPPENS!!!!
 *      90% of CPU cycles are in the function.
 *
 ***************************************************************************/
void transmit_thread(void *v) /*aka. scanning_thread() */ {

  struct ThreadPair *parms = (struct ThreadPair *)v;
  uint64_t i, start, end;
  const struct Masscan *masscan = parms->masscan;
  uint64_t retries = masscan->retries;
  uint64_t rate;
  unsigned r = (unsigned)retries + 1;
  uint64_t range;
  uint64_t range_ipv6;
  struct BlackRock blackrock;
  uint64_t count_ipv4, count_ipv6;
  massint128_t count_ipv6_128;
  struct Throttler *throttler = parms->throttler;
  struct TemplateSet pkt_template;
  struct Adapter *adapter = parms->adapter;
  uint64_t packets_sent = 0;
  size_t increment = (masscan->shard.of - 1) + masscan->nic_count;
  ipv4address_t src_ipv4, src_ipv4_mask;
  ipv6address_t src_ipv6, src_ipv6_mask;
  unsigned src_port, src_port_mask;
  uint64_t seed = masscan->seed;
  uint64_t repeats = 0; /* --infinite repeats */
  uint64_t entropy = masscan->seed;
  bool need_fix_rate = false;

  count_ipv4 = rangelist_count(&masscan->targets.ipv4);
  count_ipv6 = range6list_count(&count_ipv6_128, &masscan->targets.ipv6)->lo;

  pixie_set_thread_name("transmit");

  if (masscan->max_rate > (double)UINT64_MAX) {
    LOG(LEVEL_ERROR, "Rate overflowed %f\n", masscan->max_rate);
    rate = UINT64_MAX;
  } else {
    rate = (uint64_t)masscan->max_rate;
  }

  LOG(LEVEL_INFO, "[+] starting transmit thread #%" PRIuPTR "\n",
      parms->nic_index);
  if (templ_copy(&pkt_template, parms->tmplset) == NULL) {
    LOG(LEVEL_INFO, "templ_copy erro\n");
  }

  /* export a pointer to this variable outside this threads so
   * that the 'status' system can print the rate of syns we are
   * sending */
  parms->total_syns = 0;

  /* Normally, we have just one source address. In special cases, though
   * we can have multiple. */
  adapter_get_source_addresses(masscan, parms->nic_index, &src_ipv4,
                               &src_ipv4_mask, &src_port, &src_port_mask,
                               &src_ipv6, &src_ipv6_mask);

  /* "THROTTLER" rate-limits how fast we transmit, set with the
   * --max-rate parameter */
  throttler_start(throttler, masscan->max_rate / masscan->nic_count);

infinite:

  /* Create the shuffler/randomizer. This creates the 'range' variable,
   * which is simply the number of IP addresses times the number of
   * ports.
   * IPv6: low index will pick addresses from the IPv6 ranges, and high
   * indexes will pick addresses from the IPv4 ranges. */
  range = count_ipv4 * rangelist_count(&masscan->targets.ports) +
          count_ipv6 * rangelist_count(&masscan->targets.ports);
  range_ipv6 = count_ipv6 * rangelist_count(&masscan->targets.ports);
  blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

  /* Calculate the 'start' and 'end' of a scan. One reason to do this is
   * to support --shard, so that multiple machines can co-operate on
   * the same scan. Another reason to do this is so that we can bleed
   * a little bit past the end when we have --retries. Yet another
   * thing to do here is deal with multiple network adapters, which
   * is essentially the same logic as shards. */
  start = masscan->resume.index + (masscan->shard.one - 1) + parms->nic_index;
  end = range;
  if (masscan->resume.count && end > start + masscan->resume.count)
    end = start + masscan->resume.count;
  end += retries * range;

  /* -----------------
   * the main loop
   * -----------------*/
  pixie_wait_barrier(parms->barrier_main_loop);
  LOG(LEVEL_DEBUG_1, "THREAD: xmit: starting main loop: [%llu..%llu]\n", start,
      end);
  for (i = start; i < end;) {
    uint64_t batch_size, left_batch;

    /*Do a batch of many packets at a time. That because per-packet
     * throttling is expensive at 10-million pps, so we reduce the
     * per-packet cost by doing batches. At slower rates, the batch
     * size will always be one. (--max-rate) */
    left_batch = batch_size = throttler_next_batch(throttler, packets_sent);

    /* Transmit packets from other thread, when doing --banners. This
     * takes priority over sending SYN packets. If there is so much
     * activity grabbing banners that we cannot transmit more SYN packets,
     * then "batch_size" will get decremented to zero, and we won't be
     * able to transmit SYN packets. */
    stack_flush_packets(parms->stack, adapter, &packets_sent, &left_batch);

    if (masscan->is_tranquility) {
      left_batch =
          rate_adjustment(parms, batch_size, left_batch, &need_fix_rate);
    }

    /* Transmit a bunch of packets. At any rate slower than 100,000
     * packets/second, the 'batch_size' is likely to be 1
     * packets/second, the 'batch_size' is likely to be 1. At higher
     * rates, we can't afford to throttle on a per-packet basis and
     * instead throttle on a per-batch basis. In other words, throttle
     * based on 2-at-a-time, 3-at-time, and so on, with the batch
     * size increasing as the packet rate increases. This gives us
     * very precise packet-timing for low rates below 100,000 pps,
     * while not incurring the overhead for high packet rates. */
    while (left_batch && i < end) {
      uint64_t xXx;
      uint64_t cookie;

      /*
       * RANDOMIZE THE TARGET:
       *  This is kinda a tricky bit that picks a random IP and port
       *  number in order to scan. We monotonically increment the
       *  index 'i' from [0..range]. We then shuffle (randomly transmog)
       *  that index into some other, but unique/1-to-1, number in the
       *  same range. That way we visit all targets, but in a random
       *  order. Then, once we've shuffled the index, we "pick" the
       *  IP address and port that the index refers to.
       */
      xXx = (i + (r--) * rate);
      if (rate > range) {
        xXx %= range;
      } else {
        while (xXx >= range) {
          xXx -= range;
        }
      }
      xXx = blackrock_shuffle(&blackrock, xXx);
      if (xXx < range_ipv6) {
        ipv6address_t ip_them;
        unsigned port_them;
        ipv6address_t ip_me;
        unsigned port_me;

        range6list_pick(&ip_them, &masscan->targets.ipv6, xXx % count_ipv6);
        port_them = rangelist_pick(&masscan->targets.ports, xXx / count_ipv6);

        ip_me = src_ipv6;
        port_me = src_port;

        cookie = syn_cookie_ipv6(&ip_them, port_them, &ip_me, port_me, entropy);

        rawsock_send_probe_ipv6(
            adapter, &ip_them, port_them, &ip_me, port_me, (unsigned)cookie,
            left_batch == 1, /* flush queue on last packet in batch */
            &pkt_template);

        /* Our index selects an IPv6 target */
      } else {
        /* Our index selects an IPv4 target. In other words, low numbers
         * index into the IPv6 ranges, and high numbers index into the
         * IPv4 ranges. */
        ipv4address_t ip_them;
        unsigned port_them;
        ipv4address_t ip_me;
        unsigned port_me;

        xXx -= range_ipv6;

        ip_them = rangelist_pick(&masscan->targets.ipv4, xXx % count_ipv4);
        port_them = rangelist_pick(&masscan->targets.ports, xXx / count_ipv4);

        /*
         * SYN-COOKIE LOGIC
         *  Figure out the source IP/port, and the SYN cookie
         */
        if (src_ipv4_mask > 1 || src_port_mask > 1) {
          unsigned tmp_i_repeats = (unsigned)(i + repeats);
          unsigned tmp_x = (unsigned)xXx;

          uint64_t ck =
              syn_cookie_ipv4(&tmp_i_repeats, (unsigned)((i + repeats) >> 32),
                              &tmp_x, (unsigned)(xXx >> 32), entropy);
          port_me = src_port + (ck & src_port_mask);
          ip_me = src_ipv4 + ((ck >> 16) & src_ipv4_mask);
        } else {
          ip_me = src_ipv4;
          port_me = src_port;
        }
        cookie = syn_cookie_ipv4(&ip_them, port_them, &ip_me, port_me, entropy);

        /*
         * SEND THE PROBE
         *  This is sorta the entire point of the program, but little
         *  exciting happens here. The thing to note that this may
         *  be a "raw" transmit that bypasses the kernel, meaning
         *  we can call this function millions of times a second.
         */
        rawsock_send_probe_ipv4(
            adapter, &ip_them, port_them, &ip_me, port_me, (unsigned)cookie,
            left_batch == 1, /* flush queue on last packet in batch */
            &pkt_template);
      }

      left_batch--;
      packets_sent++;
      parms->total_syns++;

      /*
       * SEQUENTIALLY INCREMENT THROUGH THE RANGE
       *  Yea, I know this is a puny 'i++' here, but it's a core feature
       *  of the system that is linearly increments through the range,
       *  but produces from that a shuffled sequence of targets (as
       *  described above). Because we are linearly incrementing this
       *  number, we can do lots of creative stuff, like doing clever
       *  retransmits and sharding.
       */
      if (r == 0) {
        i += increment; /* <------ increment by 1 normally, more with
                           shards/nics */
        r = (unsigned)retries + 1;
      }

    } /* end of batch */

    /* save our current location for resuming, if the user pressed
     * <ctrl-c> to exit early */
    parms->my_index = i;

    /* If the user pressed <ctrl-c>, then we need to exit. In case
     * the user wants to --resume the scan later, we save the current
     * state in a file */
    if (is_tx_done) {
      break;
    }
  }

  /*
   * --infinite
   *  For load testing, go around and do this again
   */
  if (masscan->is_infinite && !is_tx_done) {
    seed++;
    repeats++;
    goto infinite;
  }

  /*
   * Flush any untransmitted packets. High-speed mechanisms like Windows
   * "sendq" and Linux's "PF_RING" queue packets and transmit many together,
   * so there may be some packets that we've queued but not yet transmitted.
   * This call makes sure they are transmitted.
   */
  rawsock_flush(adapter);

  /* Wait until the receive thread realizes the scan is over */
  LOG(LEVEL_INFO, "[+] transmit thread #%" PRIuPTR " complete\n",
      parms->nic_index);

  /* We are done transmitting. However, response packets will take several
   * seconds to arrive. Therefore, sit in short loop waiting for those
   * packets to arrive. Pressing <ctrl-c> a second time will exit this
   * prematurely. */
  while (!is_rx_done) {
    unsigned k;
    uint64_t batch_size;

    for (k = 0; k < 1000; k++) {
      /* Only send a few packets at a time, throttled according to the max
       * --max-rate set by the user */
      batch_size = throttler_next_batch(throttler, packets_sent);
      /* Transmit packets from the receive thread */
      stack_flush_packets(parms->stack, adapter, &packets_sent, &batch_size);
      /* Make sure they've actually been transmitted, not just queued up for
       * transmit */
      rawsock_flush(adapter);
      pixie_usleep(100);
    }
  }

  /* Thread is about to exit */
  parms->done_transmitting = 1;
  template_packet_cleanup(&pkt_template);
  LOG(LEVEL_INFO, "[+] exiting transmit thread #%" PRIuPTR "\n",
      parms->nic_index);
}

#define BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST 16384

int transmit_selftest() {
  {
    // Exceeding LIMIT_RECV_QUEUE_RATE_FIX
    size_t i;
    int err;
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};

    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    for (i = 0; i < LIMIT_RECV_QUEUE_RATE_FIX + 1; i++) {
      err = rte_ring_sp_enqueue(parms.stack->recv_queue, (void *)i);
      REGRESS(err == 0);
    }

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate != false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    while (!rte_ring_empty(parms.stack->recv_queue)) {
      rte_ring_sc_dequeue(parms.stack->recv_queue, (void **)&i);
    }
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Not exceeding LIMIT_RECV_QUEUE_RATE_FIX
    size_t i;
    int err;
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    for (i = 0; i < LIMIT_RECV_QUEUE_RATE_FIX; i++) {
      err = rte_ring_sp_enqueue(parms.stack->recv_queue, (void *)i);
      REGRESS(err == 0);
    }

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    while (!rte_ring_empty(parms.stack->recv_queue)) {
      rte_ring_sc_dequeue(parms.stack->recv_queue, (void **)&i);
    }
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Exceeding LIMIT_RECV_LAG_RATE_FIX
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    parms.secs_current_recv = 1;
    parms.usecs_current_recv = 0;
    parms.secs_last_recv = 1;
    parms.usecs_last_recv = (uint64_t)LIMIT_RECV_LAG_RATE_FIX + 1;

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate != false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Not exceeding LIMIT_RECV_LAG_RATE_FIX
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    parms.secs_current_recv = 1;
    parms.usecs_current_recv = 0;
    parms.secs_last_recv = 1;
    parms.usecs_last_recv = (uint64_t)LIMIT_RECV_LAG_RATE_FIX;

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Normal
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 800);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // LIMIT_RECV_QUEUE
    size_t i;
    int err;
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    for (i = 0; i < LIMIT_RECV_QUEUE; i++) {
      err = rte_ring_sp_enqueue(parms.stack->recv_queue, (void *)i);
      REGRESS(err == 0);
    }

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    while (!rte_ring_empty(parms.stack->recv_queue)) {
      rte_ring_sc_dequeue(parms.stack->recv_queue, (void **)&i);
    }
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // == LIMIT_RECV_LAG
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    parms.secs_current_recv = 1;
    parms.usecs_current_recv = 0;
    parms.secs_last_recv = 1;
    parms.usecs_last_recv = (uint64_t)LIMIT_RECV_LAG;

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // < LIMIT_RECV_QUEUE and > 0
    size_t i;
    int err;
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    for (i = 0; i < 1; i++) {
      err = rte_ring_sp_enqueue(parms.stack->recv_queue, (void *)i);
      REGRESS(err == 0);
    }

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 600);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    while (!rte_ring_empty(parms.stack->recv_queue)) {
      rte_ring_sc_dequeue(parms.stack->recv_queue, (void **)&i);
    }
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // < LIMIT_RECV_LAG and > 0
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = false;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);
    parms.secs_current_recv = 1;
    parms.usecs_current_recv = 0;
    parms.secs_last_recv = 1;
    parms.usecs_last_recv = 100;

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 600);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Fix rate if queue is empty
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 800;
    bool need_fix_rate = true;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 800);
    REGRESS(need_fix_rate == false);
    REGRESS((size_t)parms.throttler->max_rate == 70);
    rte_ring_free(parms.stack->recv_queue);
  }

  {
    // Not fix rate if queue is not empty
    struct ThreadPair parms = {0};
    struct stack_t stack[1] = {{0}};
    int64_t batch_size = 1000;
    int64_t left_batch = 0;
    bool need_fix_rate = true;
    parms.throttler->max_rate = 100;
    parms.stack = stack;
    parms.stack->recv_queue = rte_ring_create(
        BUFFER_COUNT_RECV_FOR_TRANSMIT_SELFTEST, RING_F_SP_ENQ | RING_F_SC_DEQ);

    left_batch =
        rate_adjustment(&parms, batch_size, left_batch, &need_fix_rate);
    REGRESS(left_batch == 0);
    REGRESS(need_fix_rate != false);
    REGRESS((size_t)parms.throttler->max_rate == 100);
    rte_ring_free(parms.stack->recv_queue);
  }

  return 0;
}
