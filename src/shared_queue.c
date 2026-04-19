#include "../include/shared_queue.h"
#include <stdlib.h>

int shared_queue_create(shared_queue_t *queue, ring_buffer_t *rb,
                        pthread_mutex_t *mutex, pthread_cond_t *not_empty_cond,
                        pthread_cond_t *has_space) {
  queue->rb = rb;
  queue->mutex = *mutex;
  queue->not_empty = *not_empty_cond;
  queue->has_space = *has_space;
  queue->producer_finished = false;
  pthread_mutex_init(mutex, NULL);
  return 0;
}

int shared_queue_destroy(shared_queue_t *queue) {
  pthread_mutex_destroy(&queue->mutex);
  return 0;
}
