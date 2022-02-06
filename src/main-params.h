#ifndef MAIN_MAINPARAMS_H
#define MAIN_MAINPARAMS_H

#include <stdint.h>

#include "main-throttle.h"
#include "massip-addr.h"
#include "stack-queue.h"
#include "stack-src.h"
#include "templ-pkt.h"

/***************************************************************************
 * We create a pair of transmit/receive threads for each network adapter.
 * This structure contains the parameters we send to each pair.
 ***************************************************************************/
struct ThreadPair {
  /** This points to the central configuration. Note that it's 'const',
   * meaning that the thread cannot change the contents. That'd be
   * unsafe */
  const struct Masscan *masscan;

  /** The adapter used by the thread-pair. Normally, thread-pairs have
   * their own network adapter, especially when doing PF_RING
   * clustering. */
  struct Adapter *adapter;
  struct stack_t *stack;

  /* The index of the network adapter that we are using for this
   * thread-pair. This is an index into the "masscan->nic[]"
   * array.
   *
   * NOTE: this is also the "thread-id", because we create one
   * transmit/receive thread pair per NIC. */
  size_t nic_index;

  /* A copy of the master 'index' variable. This is just advisory for
   * other threads, to tell them how far we've gotten. */
  volatile uint64_t my_index;

  /* This is used both by the transmit and receive thread for
   * formatting packets */
  struct TemplateSet tmplset[1];

  /* The current IP address we are using for transmit/receive. */
  struct stack_src_t _src_;

  macaddress_t source_mac;
  macaddress_t router_mac_ipv4;
  macaddress_t router_mac_ipv6;

  uint64_t done_transmitting;
  uint64_t done_receiving;

  double pt_start;

  struct Throttler throttler[1];

  volatile int64_t total_synacks;
  volatile int64_t total_tcbs;
  uint64_t total_syns;
  uint64_t secs_last_recv;
  uint64_t usecs_last_recv;
  uint64_t secs_current_recv;
  uint64_t usecs_current_recv;

  size_t thread_handle_xmit;
  size_t thread_handle_recv;
  void *barrier_main_loop;
};

#endif