#include "smackqueue.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************************************************************************
 * Build a queue so that we can do a breadth-first enumeration of the
 * sub-patterns
 ****************************************************************************/
struct QueueElement {
  size_t m_data;
  struct QueueElement *m_next;
};
struct Queue {
  struct QueueElement *m_head;
  struct QueueElement *m_tail;
};

struct Queue *queue_create(void) {
  struct Queue *queue;
  queue = (struct Queue *)malloc(sizeof(*queue));
  if (queue == NULL) {
    LOG(LEVEL_ERROR, "%s: out of memory error\n", "smack");
    exit(1);
  }
  memset(queue, 0, sizeof(*queue));
  return queue;
}

void queue_destroy(struct Queue *queue) {
  if (queue == NULL)
    return;
  while (queue_has_more_items(queue))
    dequeue(queue);
  free(queue);
}

void enqueue(struct Queue *queue, size_t data) {
  struct QueueElement *element;

  element = (struct QueueElement *)malloc(sizeof(struct QueueElement));
  if (element == NULL) {
    LOG(LEVEL_ERROR, "%s: out of memory error\n", "smack");
    exit(1);
  }

  if (queue->m_head == NULL) {
    /* If nothing in the queue, initialize the queue with the
     * first data */
    queue->m_head = element;
  } else {
    /* Else, add the data to the tail of the queue */
    queue->m_tail->m_next = element;
  }

  element->m_data = data;
  element->m_next = NULL;
  queue->m_tail = element;
}

size_t dequeue(struct Queue *queue) {
  if (queue->m_head == NULL)
    return 0;
  else {
    struct QueueElement *element;
    size_t result;

    element = queue->m_head;
    result = element->m_data;
    queue->m_head = element->m_next;

    free(element);
    return result;
  }
}

unsigned queue_has_more_items(struct Queue *queue) {
  return queue->m_head != NULL;
}
