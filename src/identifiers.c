#include "../include/identifiers.h"

ip_address_t ip_from_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) |
         ((uint32_t)d);
}

mac_address_t mac_from_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                             uint8_t e, uint8_t f) {
  return ((uint64_t)a << 40) | ((uint64_t)b << 32) | ((uint64_t)c << 24) |
         ((uint64_t)d << 16) | ((uint64_t)e << 8) | ((uint64_t)f);
}
