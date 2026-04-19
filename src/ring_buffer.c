#include "../include/ring_buffer.h"
#include <stdio.h>
#include <stdlib.h>

int to_index(size_t num, size_t capacity) { return num % capacity; }

int ring_buffer_create(ring_buffer_t *rb, size_t capacity) {
  uintptr_t *qbuf = malloc(sizeof(uintptr_t *) * capacity);
  rb->size = 0;
  rb->capacity = 10;
  rb->tail = 0;
  rb->head = 0;
  rb->buffer = qbuf;
  return 0;
}

void ring_buffer_destroy(ring_buffer_t *ring_buffer) {
  free(ring_buffer->buffer);
}

int ring_buffer_push(ring_buffer_t *rb, uintptr_t data) {
  rb->size++;
  rb->buffer[to_index(rb->head++, rb->capacity)] = data;
  return 0;
}

int ring_buffer_pop(ring_buffer_t *rb, uintptr_t *out) {
  if (rb->size == 0) {
    return -1;
  }
  rb->size--;
  *out = rb->buffer[to_index(rb->tail++, rb->capacity)];
  return 0;
}

bool ring_buffer_full(ring_buffer_t *rb) { return rb->size >= rb->capacity; }
bool ring_buffer_empty(ring_buffer_t *rb) { return rb->size <= 0; }
