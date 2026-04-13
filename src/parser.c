#include "../include/parser.h"
#include "../include/packet.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

const int kIPHeaderSize = 14;
const int kTCPHeaderSize = 20;
const int kUDPHeaderSize = 8;

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

  uint16_t flags_fo = data[6] << 8 | data[7];
  out->flags = flags_fo >> 13;
  out->fragment_offset = flags_fo & 0x1FFF;

  out->ttl = data[8];
  out->protocol = data[9];
  out->checksum = data[10] << 8 | data[11];
  out->src = data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15];
  out->dst = data[16] << 24 | data[17] << 16 | data[18] << 8 | data[19];

  return 0;
}

int parse_tcp(const uint8_t *data, size_t total_length, TCPHeader *out) {
  out->src_port = data[0] << 8 | data[1];
  out->dst_port = data[2] << 8 | data[3];
  out->seq_number = 1;
  out->seq_number = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
  out->ack_number = data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11];

  uint16_t len_flags = data[12] << 8 | data[13];
  out->hdr_len = len_flags >> 12;
  out->flags = len_flags & 0x0FFF;

  out->window = data[14] << 8 | data[15];
  out->checksum = data[16] << 8 | data[17];
  out->urgent_pointer = data[18] << 8 | data[19];

  size_t payload_size = total_length - kTCPHeaderSize - (out->hdr_len * 4);
  out->payload = malloc(payload_size);
  out->payload_size = payload_size;
  memcpy(out->payload, data + 32, payload_size);
  return 0;
}

int parse_udp(const uint8_t *data, UDPHeader *out) {
  out->src_port = data[0] << 8 | data[1];
  out->dst_port = data[2] << 8 | data[3];
  out->length = data[4] << 8 | data[5];
  out->checksum = data[6] << 8 | data[7];
  out->payload = malloc(out->length);
  memcpy(out->payload, data + kUDPHeaderSize, out->length - kUDPHeaderSize);
  return 0;
}
