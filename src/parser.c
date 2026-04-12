#include "../include/packet.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>

int parse_ethframe(const uint8_t *data, EthernetFrame *out) {
  memcpy(out->dst, data, 6);
  memcpy(out->src, data + 6, 6);

  out->type = data[12] << 8 | data[13];

  return 0;
}

int parse_ipv4(const uint8_t *data, size_t len, IPHeader *out) {
  if (len < 20)
    return -1;

  uint8_t vhl = data[0];
  out->version = vhl >> 4;
  out->ihl = vhl & 0x0F;

  uint8_t ds = data[1];
  out->dscp = ds >> 2;
  out->ecn = ds & 0x03;

  out->total_length = data[2] << 8 | data[3];
  out->identification = data[4] << 8 | data[5];
  out->flags = data[6] << 3;
  out->ttl = data[8];
  out->protocol = data[9];
  out->checksum = data[10] << 8 | data[11];
  out->src = data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15];
  out->dst = data[16] << 24 | data[17] << 16 | data[18] << 8 | data[19];

  return 0;
}
