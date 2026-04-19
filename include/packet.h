#ifndef INCLUDE_PACKET_H_
#define INCLUDE_PACKET_H_

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
} ipv4_header_t;

typedef struct {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
} ethernet_frame_t;

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
} tcp_pkt_t;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
  uint8_t *payload;
} udp_pkt_t;

typedef struct {
  // TODO: Implement ICMP packets
} icmp_pkt_t;

typedef enum {
  PACKET_TYPE_TCP,
  PACKET_TYPE_UDP,
  PACKET_TYPE_ICMP,
} packet_type_t;

#endif // INCLUDE_PACKET_H_
