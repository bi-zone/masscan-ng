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
void tcp_transmit(struct InteractiveData *more, void *payload, size_t length,
                  unsigned flags) {

  void *new_payload = NULL;
  size_t new_length = 0;

  assert(more != NULL);

  if (payload == NULL || length == 0) {
    if (payload != NULL && (flags & TCPTRAN_DYNAMIC)) {
      free(payload);
    }
    return;
  }

  if (more->m_payload == NULL || more->m_length == 0) {
    assert(more->m_payload == NULL && more->m_length == 0);
    assert(more->is_payload_dynamic == false);
    more->m_payload = payload;
    more->m_length = (unsigned)length;
    if (flags & TCPTRAN_DYNAMIC) {
      more->is_payload_dynamic = true;
    }
    return;
  }

  new_length = (size_t)more->m_length + length;
  if (more->is_payload_dynamic) {
    new_payload = realloc((void *)more->m_payload, new_length);
  } else {
    new_payload = malloc(new_length);
  }

  if (new_payload == NULL) {
    if (flags & TCPTRAN_DYNAMIC) {
      free((void *)payload);
    }
    return;
  }

  if (!more->is_payload_dynamic) {
    memcpy(new_payload, more->m_payload, (size_t)more->m_length);
    more->is_payload_dynamic = true;
  }
  memcpy((char *)new_payload + (size_t)more->m_length, payload, length);

  if (flags & TCPTRAN_DYNAMIC) {
    free((void *)payload);
  }

  more->m_payload = new_payload;
  more->m_length = (unsigned)new_length;
  return;
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
  unsigned flags;

  if (more1 == NULL) {
    return;
  }

  flags = 0;
  if (more1->is_payload_dynamic) {
    flags |= TCPTRAN_DYNAMIC;
  }
  tcp_transmit(more2, more1->m_payload, more1->m_length, flags);
  memset(more1, 0, sizeof(*more1));

  flags = 0;
  if (more2->is_payload_dynamic) {
    flags |= TCPTRAN_DYNAMIC;
  }
  tcp_transmit(more1, more2->m_payload, more2->m_length, flags);
  memset(more2, 0, sizeof(*more2));
  return;
}

#ifndef __clang_analyzer__
int interactive_data_selftest() {

  int x = 0;
  void *data = NULL;
  struct InteractiveData more1 = {0};
  struct InteractiveData more2 = {0};

  tcp_transmit(&more1, "45", 2, 0);
  tcp_transmit(&more2, "123", 3, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 0\n");
    x += 1;
  }
  free_interactive_data(&more1);

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
    x += 1;
  }
  free_interactive_data(&more1);

  data = malloc(3);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  tcp_transmit(&more1, "45", 2, 0);
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 2\n");
    x += 1;
  }
  free_interactive_data(&more1);

  data = malloc(2);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  memcpy(data, "45", 2);
  tcp_transmit(&more1, data, 2, TCPTRAN_DYNAMIC);
  data = malloc(3);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "12345", 5) != 0 || more1.m_length != 5) {
    LOG(LEVEL_ERROR, "interactive_data: failed 3\n");
    x += 1;
  }
  free_interactive_data(&more1);

  tcp_transmit(&more2, "123", 3, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "123", 3) != 0 || more1.m_length != 3) {
    LOG(LEVEL_ERROR, "interactive_data: failed 4\n");
    x += 1;
  }
  free_interactive_data(&more1);

  data = malloc(3);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  memcpy(data, "123", 3);
  tcp_transmit(&more2, data, 3, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "123", 3) != 0 || more1.m_length != 3) {
    LOG(LEVEL_ERROR, "interactive_data: failed 5\n");
    x += 1;
  }
  free_interactive_data(&more1);

  tcp_transmit(&more1, "45", 2, 0);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "45", 2) != 0 || more1.m_length != 2) {
    LOG(LEVEL_ERROR, "interactive_data: failed 6\n");
    x += 1;
  }
  free_interactive_data(&more1);

  data = malloc(2);
  if (data == NULL) {
    LOG(LEVEL_ERROR, "Can't alloc\n");
    return 1;
  }
  memcpy(data, "45", 2);
  tcp_transmit(&more1, data, 2, TCPTRAN_DYNAMIC);
  append_interactive_data(&more1, &more2);
  if (memcmp(more1.m_payload, "45", 2) != 0 || more1.m_length != 2) {
    LOG(LEVEL_ERROR, "interactive_data: failed 7\n");
    x += 1;
  }
  free_interactive_data(&more1);

  return x;
}
#endif