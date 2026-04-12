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
  uint32_t dst;
  uint32_t src;
  uint8_t type;
} EthernetFrame;

#endif // INCLUDE_INCLUDE_PACKET_H_
