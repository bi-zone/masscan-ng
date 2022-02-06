#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "pixie-timer.h"
#include "rawsock.h"
#include "stack-queue.h"
#include "util-malloc.h"

struct PacketBufferTransmit *
stack_get_transmit_packetbuffer(struct stack_t *stack) {
  int err;
  struct PacketBufferTransmit *response = NULL;

  for (err = 1; err;) {
    err =
        rte_ring_mc_dequeue(stack->transmit_packet_buffers, (void **)&response);
    if (err != 0) {
      /* Pause and wait for a buffer to become available */
      pixie_usleep(1000);
    }
  }
  return response;
}

void stack_transmit_packetbuffer(struct stack_t *stack,
                                 struct PacketBufferTransmit *response) {
  int err;
  for (err = 1; err;) {
    err = rte_ring_mp_enqueue(stack->transmit_queue, response);
    if (err) {
      LOG(LEVEL_WARNING, "[-] transmit queue full (should be impossible)\n");
      pixie_usleep(1000);
    }
  }
}

struct PacketBufferRecv *stack_get_recv_packetbuffer(struct stack_t *stack) {
  int err;
  struct PacketBufferRecv *response = NULL;

  for (err = 1; err;) {
    err = rte_ring_sc_dequeue(stack->recv_packet_buffers, (void **)&response);
    if (err != 0) {
      /* Pause and wait for a buffer to become available */
      pixie_usleep(1000);
    }
  }
  return response;
}

void stack_recv_packetbuffer(struct stack_t *stack,
                             struct PacketBufferRecv *response) {
  int err;
  for (err = 1; err;) {
    err = rte_ring_sp_enqueue(stack->recv_queue, response);
    if (err) {
      LOG(LEVEL_WARNING, "[-] recv queue full (should be impossible)\n");
      pixie_usleep(1000);
    }
  }
}

/***************************************************************************
 * The receive thread doesn't transmit packets. Instead, it queues them
 * up on the transmit thread. Every so often, the transmit thread needs
 * to flush this transmit queue and send everything.
 *
 * This is an inherent design issue trying to send things as batches rather
 * than individually. It increases latency, but increases performance. We
 * don't really care about latency.
 ***************************************************************************/
void stack_flush_packets(struct stack_t *stack, struct Adapter *adapter,
                         uint64_t *packets_sent, uint64_t *batchsize) {

  /* Send a batch of queued packets */
  for (; (*batchsize); (*batchsize)--) {
    int err;
    struct PacketBufferTransmit *p;

    /* Get the next packet from the transmit queue. This packet was
     * put there by a receive thread, and will contain things like
     * an ACK or an HTTP request */
    err = rte_ring_sc_dequeue(stack->transmit_queue, (void **)&p);
    if (err) {
      break; /* queue is empty, nothing to send */
    }

    /* Actually send the packet */
    rawsock_send_packet(adapter, p->px, (unsigned)p->length, true);

    /* Now that we are done with the packet, put it on the free list
     * of buffers that the transmit thread can reuse */
    for (err = 1; err;) {
      err = rte_ring_sp_enqueue(stack->transmit_packet_buffers, p);
      if (err) {
        LOG(LEVEL_WARNING,
            "[-] transmit packet buffers full (should be impossible)\n");
        pixie_usleep(10000);
      }
    }

    /* Remember that we sent a packet, which will be used in
     * throttling. */
    (*packets_sent)++;
  }
}

struct stack_t *stack_create(macaddress_t source_mac, struct stack_src_t *src,
                             size_t recv_thread_count) {

  struct stack_t *stack;
  size_t i;
  int err;

  stack = CALLOC(1, sizeof(*stack));
  stack->source_mac = source_mac;
  stack->src = src;
  stack->recv_thread_count = recv_thread_count;

  /* Allocate packet buffers for sending */
  stack->transmit_packet_buffers =
      rte_ring_create(BUFFER_COUNT_TRANSMIT, RING_F_SP_ENQ);
  stack->transmit_queue = rte_ring_create(BUFFER_COUNT_TRANSMIT, RING_F_SC_DEQ);
  for (i = 0; i < BUFFER_COUNT_TRANSMIT - 1; i++) {
    struct PacketBufferTransmit *p;

    p = MALLOC(sizeof(*p));
    err = rte_ring_sp_enqueue(stack->transmit_packet_buffers, p);
    if (err) {
      /* I dunno why but I can't queue all 256 packets, just 255 */
      LOG(LEVEL_WARNING, "[-] packet_buffers: enqueue: error %d\n", err);
    }
  }

  stack->recv_packet_buffers =
      rte_ring_create(BUFFER_COUNT_RECV, RING_F_SC_DEQ);
  stack->recv_queue =
      rte_ring_create(BUFFER_COUNT_RECV, RING_F_SP_ENQ | RING_F_SC_DEQ);
  for (i = 0; i < stack->recv_thread_count; i++) {
    stack->recv_thread[i].recv_th_queue =
        rte_ring_create(BUFFER_COUNT_RECV, RING_F_SP_ENQ | RING_F_SC_DEQ);
  }
  for (i = 0; i < BUFFER_COUNT_RECV - 1; i++) {
    struct PacketBufferRecv *p;

    p = MALLOC(sizeof(*p));
    err = rte_ring_mp_enqueue(stack->recv_packet_buffers, p);
    if (err) {
      /* I dunno why but I can't queue all 256 packets, just 255 */
      LOG(LEVEL_WARNING, "[-] packet_buffers: enqueue: error %d\n", err);
    }
  }

  return stack;
}

size_t stack_recv_queue_count(struct stack_t *stack) {
  size_t i;
  size_t count_recv_queue = 0;
  count_recv_queue = (size_t)rte_ring_count(stack->recv_queue);
  for (i = 0; i < stack->recv_thread_count; i++) {
    count_recv_queue +=
        (size_t)rte_ring_count(stack->recv_thread[i].recv_th_queue);
  }
  return count_recv_queue;
}

void stack_destroy(struct stack_t *stack) {
  struct PacketBufferTransmit *p_transmit;
  struct PacketBufferRecv *p_recv;
  size_t i;
  int err;

  while (true) {
    p_transmit = NULL;
    err = rte_ring_sc_dequeue(stack->transmit_queue, (void **)&p_transmit);
    if (err) {
      break; /* queue is empty */
    }
    free(p_transmit);
  }
  rte_ring_free(stack->transmit_queue);
  stack->transmit_queue = NULL;

  while (true) {
    p_transmit = NULL;
    err = rte_ring_sc_dequeue(stack->transmit_packet_buffers,
                              (void **)&p_transmit);
    if (err) {
      break; /* queue is empty */
    }
    free(p_transmit);
  }
  rte_ring_free(stack->transmit_packet_buffers);
  stack->transmit_packet_buffers = NULL;

  for (i = 0; i < stack->recv_thread_count; i++) {
    while (true) {
      p_recv = NULL;
      err = rte_ring_sc_dequeue(stack->recv_thread[i].recv_th_queue,
                                (void **)&p_recv);
      if (err) {
        break; /* queue is empty */
      }
      free(p_recv);
    }
    rte_ring_free(stack->recv_thread[i].recv_th_queue);
    stack->recv_thread[i].recv_th_queue = NULL;
  }

  while (true) {
    p_recv = NULL;
    err = rte_ring_sc_dequeue(stack->recv_queue, (void **)&p_recv);
    if (err) {
      break; /* queue is empty */
    }
    free(p_recv);
  }
  rte_ring_free(stack->recv_queue);
  stack->recv_queue = NULL;

  while (true) {
    p_recv = NULL;
    err = rte_ring_sc_dequeue(stack->recv_packet_buffers, (void **)&p_recv);
    if (err) {
      break; /* queue is empty */
    }
    free(p_recv);
  }
  rte_ring_free(stack->recv_packet_buffers);
  stack->recv_packet_buffers = NULL;

  free(stack);
}
