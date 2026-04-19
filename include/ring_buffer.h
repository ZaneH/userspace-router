#ifndef INCLUDE_RING_BUFFER_H_
#define INCLUDE_RING_BUFFER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  /// Index of the writer
  size_t head;
  /// Index of the reader
  size_t tail;
  /// Maximum number of individual elements that fit into the queue
  size_t capacity;
  /// Current size of the queue. Incremented by writes, decremented by reads.
  size_t size;
  /// Data buffer
  uintptr_t *buffer;
} ring_buffer_t;

int ring_buffer_create(ring_buffer_t *rb, size_t capacity);
void ring_buffer_destroy(ring_buffer_t *rb);
int ring_buffer_push(ring_buffer_t *rb, uintptr_t data);
int ring_buffer_pop(ring_buffer_t *rb, uintptr_t *out);
bool ring_buffer_full(ring_buffer_t *rb);
bool ring_buffer_empty(ring_buffer_t *rb);

#endif // INCLUDE_RING_BUFFER_H_
