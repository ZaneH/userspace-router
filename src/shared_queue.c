#include "../include/shared_queue.h"
#include <stdlib.h>

int shared_queue_create(shared_queue_t *queue, size_t capacity) {
  ring_buffer_create(&queue->rb, capacity);
  queue->producer_finished = false;
  pthread_mutex_init(&queue->mutex, NULL);
  return 0;
}

int shared_queue_destroy(shared_queue_t *queue) {
  pthread_mutex_destroy(&queue->mutex);
  ring_buffer_destroy(&queue->rb);
  return 0;
}
