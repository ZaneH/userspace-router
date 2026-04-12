#include "../include/packet.h"
#include <arpa/inet.h>
#include <stddef.h>

int parse_ipv4(const uint8_t *data, size_t len, IPHeader *out) {
  if (len < 20)
    return -1;

  uint8_t vhl = data[0];
  out->version = vhl >> 4;
  out->ihl = vhl & 0x0F;

  out->identification = ntohs(*(uint16_t *)(data + 4));

  return 0;
}
