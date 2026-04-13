#ifndef INCLUDE_INCLUDE_PACKET_H_
#define INCLUDE_INCLUDE_PACKET_H_

#include <pcap/pcap.h>

typedef struct {
  uint8_t version;
  uint8_t ihl;
  uint8_t dscp;
  uint8_t ecn;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags;
  uint16_t fragment_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
  const uint8_t *options;
  uint8_t options_len;
} IPHeader;

typedef struct {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
} EthernetFrame;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_number;
  uint32_t ack_number;
  uint8_t hdr_len;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
  uint8_t options;
  uint8_t *payload;
  size_t payload_size;
} TCPHeader;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
  uint8_t *payload;
} UDPHeader;

#endif // INCLUDE_INCLUDE_PACKET_H_
