#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <limits.h>

#include "massip-addr.h"
#include "proto-preprocess.h"
#include "receiver.h"
#include "rte-ring.h"

struct stack_src_t;
struct Adapter;

typedef struct rte_ring PACKET_QUEUE;

#define MAX_SIZE_TRANSMIT_DATA 2040
#define MAX_SIZE_RECV_DATA (ETH_FRAME_LEN)

struct PacketBufferTransmit {
  size_t length;
  unsigned char px[MAX_SIZE_TRANSMIT_DATA];
};

struct PacketBufferRecv {
  size_t length;
  unsigned secs;
  unsigned usecs;
  struct PreprocessedInfo parsed;
  unsigned char px[MAX_SIZE_RECV_DATA];
};

#define BUFFER_COUNT_TRANSMIT 16384
#define BUFFER_COUNT_RECV 65536

struct stack_t {
  PACKET_QUEUE *transmit_packet_buffers;
  PACKET_QUEUE *transmit_queue;
  PACKET_QUEUE *recv_packet_buffers;
  PACKET_QUEUE *recv_queue;
  macaddress_t source_mac;
  struct {
    PACKET_QUEUE *recv_th_queue;
  } recv_thread[MAX_THREAD_HANDLE_RECV_COUNT];
  size_t recv_thread_count;
  struct stack_src_t *src;
};

/* Get a packet-buffer that we can use to create a packet before
 * sending */
struct PacketBufferTransmit *
stack_get_transmit_packetbuffer(struct stack_t *stack);
/* Queue up the packet for sending. This doesn't send the packet immediately,
 * but puts it into a queue to be sent later, when the throttler allows it
 * to be sent. */
void stack_transmit_packetbuffer(struct stack_t *stack,
                                 struct PacketBufferTransmit *response);
struct PacketBufferRecv *stack_get_recv_packetbuffer(struct stack_t *stack);
void stack_recv_packetbuffer(struct stack_t *stack,
                             struct PacketBufferRecv *response);

void stack_flush_packets(struct stack_t *stack, struct Adapter *adapter,
                         uint64_t *packets_sent, uint64_t *batchsize);

size_t stack_recv_queue_count(struct stack_t *stack);

struct stack_t *stack_create(macaddress_t source_mac, struct stack_src_t *src,
                             size_t recv_thread_count);
void stack_destroy(struct stack_t *stack);

#endif
