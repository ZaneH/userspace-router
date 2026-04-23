#ifndef INCLUDE_SHARED_QUEUE_H_
#define INCLUDE_SHARED_QUEUE_H_

#include "ring_buffer.h"
#include <pthread.h>
#include <stdbool.h>

typedef struct {
  ring_buffer_t rb;
  pthread_mutex_t mutex;
  pthread_cond_t not_empty;
  pthread_cond_t has_space;
  bool producer_finished;
} shared_queue_t;

int shared_queue_create(shared_queue_t *queue, size_t capacity);
int shared_queue_destroy(shared_queue_t *queue);

#endif // INCLUDE_SHARED_QUEUE_H_
