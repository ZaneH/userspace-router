#ifndef INCLUDE_IDENTIFIERS_H_
#define INCLUDE_IDENTIFIERS_H_

#include <stdint.h>

typedef uint32_t ip_address_t;
typedef ip_address_t subnet_mask_t;
typedef uint64_t mac_address_t;

ip_address_t ip_from_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
mac_address_t mac_from_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                             uint8_t e, uint8_t f);

#endif // INCLUDE_IDENTIFIERS_H_
