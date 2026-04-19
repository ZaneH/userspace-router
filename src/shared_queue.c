#include "../include/shared_queue.h"
#include <stdlib.h>

int shared_queue_create(shared_queue_t *queue, ring_buffer_t *rb,
                        pthread_mutex_t *mutex,
                        pthread_cond_t *non_empty_cond) {
  shared_queue_t q = {.rb = rb,
                      .mutex = *mutex,
                      .not_empty = *non_empty_cond,
                      .producer_finished = false};
  pthread_mutex_init(mutex, NULL);
  *queue = q;
  return 0;
}
