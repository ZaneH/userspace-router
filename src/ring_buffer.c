#include "../include/ring_buffer.h"
#include <stdio.h>
#include <stdlib.h>

int to_index(size_t num, size_t capacity) { return num % capacity; }

ring_buffer_t ring_buffer_create(size_t capacity) {
  uintptr_t *qbuf = malloc(sizeof(uintptr_t) * capacity);
  ring_buffer_t rb = {
      .size = 0,
      .capacity = 10,
      .tail = 0,
      .head = 0,
      .buffer = qbuf,
  };
  return rb;
}

int ring_buffer_push(ring_buffer_t *rb, uintptr_t *data) {
  rb->size++;
  rb->buffer[to_index(rb->head++, rb->capacity)] = *data;
  return 0;
}

int ring_buffer_pop(ring_buffer_t *rb, uintptr_t *out) {
  if (rb->size == 0) {
    return -1;
  }
  rb->size--;
  uint8_t data = rb->buffer[to_index(rb->tail++, rb->capacity)];
  *out = data;
  return 0;
}

bool ring_buffer_full(ring_buffer_t *rb) { return rb->size >= rb->capacity; }
bool ring_buffer_empty(ring_buffer_t *rb) { return rb->size <= 0; }
