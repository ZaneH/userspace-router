#include "./packet.h"
#include <stddef.h>
#include <stdint.h>

int parse_ethframe(const uint8_t *data, EthernetFrame *out);
int parse_ipv4(const uint8_t *data, size_t len, IPHeader *out);
