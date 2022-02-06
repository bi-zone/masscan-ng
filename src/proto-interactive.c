#include "proto-interactive.h"
#include "logger.h"
#include "util-cross.h"
#include "util-malloc.h"

#include <assert.h>
#include <memory.h>
#include <stdlib.h>

/*
 * TODO: we need to track the memory used for this better than with malloc(),
 * such as using a preallocated array of packet buffers. But for now, I'm just
 * using malloc() 'cause I'm a lazy programmer.
 */
unsigned char *tcp_transmit_alloc(struct InteractiveData *more, size_t length) {
  /* Note using this parameter yet, but in the future, we are going to have
   * memory pools instead of heap malloc(), which will use this parameter */
  UNUSEDPARM(more);

  return MALLOC(length);
}

void tcp_close(struct InteractiveData *more) {
  if (more == NULL) {
    return;
  }
  more->is_closing = true;
}

/*
 * This doesn't actually transmit right now. Instead, marks the payload as ready
 * to transmit, which will be transmitted later
 */
void tcp_transmit(struct InteractiveData *more, const void *payload,
                  size_t length, unsigned flags) {
  assert(more != NULL);
  assert(more->m_payload == NULL && more->m_length == 0);
  assert(more->is_payload_dynamic == false);
  more->m_payload = payload;
  more->m_length = (unsigned)length;

  if (flags & TCPTRAN_DYNAMIC) {
    more->is_payload_dynamic = true;
  }
}

void free_interactive_data(struct InteractiveData *more) {
  if (more->is_payload_dynamic && more->m_payload) {
    free((void *)more->m_payload);
  }
  memset(more, 0, sizeof(struct InteractiveData));
}

// append data more1 to more2 and save to more1
void append_interactive_data(struct InteractiveData *more1,
                             struct InteractiveData *more2) {
  void *new_payload = NULL;
  size_t new_length = 0;

  if (more2->m_payload == NULL || more2->m_length == 0) {
    assert(more2->m_payload == NULL && more2->m_length == 0);
    return;
  }

  if (more1->m_payload == NULL || more1->m_length == 0) {
    assert(more1->m_payload == NULL && more1->m_length == 0);
    memcpy(more1, more2, sizeof(struct InteractiveData));
    memset(more2, 0, sizeof(struct InteractiveData));
    return;
  }

  new_length = (size_t)more1->m_length + (size_t)more2->m_length;
  new_payload = malloc(new_length);
  if (new_payload == NULL) {
    return;
  }
  memcpy(new_payload, more2->m_payload, (size_t)more2->m_length);
  memcpy((char *)new_payload + (size_t)more2->m_length, more1->m_payload,
         (size_t)more1->m_length);
  free_interactive_data(more1);
  tcp_transmit(more1, new_payload, new_length, TCPTRAN_DYNAMIC);
  return;
}

int interactive_data_selftest() {

  void *data = NULL;
  struct InteractiveData more1 = {0};
  struct InteractiveData more2 = {0};

  tcp_transmit(&more1, "45", 2, 0);
  tcp_transmit(&more2, "123", 3, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 0\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  data = malloc(2);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Out of memory\n");
    return 1;
  }
  memcpy(data, "45", 2);
  tcp_transmit(&more1, data, 2, TCPTRAN_DYNAMIC);
  tcp_transmit(&more2, "123", 3, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 1\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  tcp_transmit(&more1, "45", 2, 0);
  data = malloc(3);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 2\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  data = malloc(2);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  memcpy(data, "45", 2);
  tcp_transmit(&more1, data, 2, TCPTRAN_DYNAMIC);
  data = malloc(3);
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 3\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  tcp_transmit(&more2, "123", 3, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "123", 3) != 0 || more1.m_length != 3) {
    LOG(LEVEL_ERROR, "interactive_data: failed 4\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  data = malloc(3);
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "123", 3) != 0 || more1.m_length != 3) {
    LOG(LEVEL_ERROR, "interactive_data: failed 5\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  tcp_transmit(&more1, "45", 2, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "45", 2) != 0 || more1.m_length != 2) {
    LOG(LEVEL_ERROR, "interactive_data: failed 6\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  data = malloc(2);
  memcpy(data, "45", 2);
  tcp_transmit(&more1, data, 2, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "45", 2) != 0 || more1.m_length != 2) {
    LOG(LEVEL_ERROR, "interactive_data: failed 7\n");
    free_interactive_data(&more1);
    free_interactive_data(&more2);
    return 1;
  }
  free_interactive_data(&more1);
  free_interactive_data(&more2);

  return 0;
}