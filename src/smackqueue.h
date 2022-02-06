#ifndef SMACKQUEUE_H
#define SMACKQUEUE_H

#include <stdio.h>

struct Queue *queue_create(void);
void queue_destroy(struct Queue *queue);
void enqueue(struct Queue *queue, size_t data);
size_t dequeue(struct Queue *queue);
unsigned queue_has_more_items(struct Queue *queue);

#endif
