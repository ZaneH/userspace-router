#ifndef INCLUDE_PARSER_H_
#define INCLUDE_PARSER_H_

#include "packet.h"
#include "ring_buffer.h"
#include "routing.h"
#include "shared_queue.h"
#include <stddef.h>
#include <stdint.h>

#define SIZE_ETHERNET 14
#define SIZE_TCP 20
#define SIZE_UDP 8

int read_parse_route_pcap_file(const char *filename, router_t *router);

int parse_ethframe(const uint8_t *data, ethernet_frame_t *out);
int parse_ipv4(const uint8_t *data, size_t len, ipv4_header_t *out);
int parse_tcp(const uint8_t *data, size_t total_length, tcp_pkt_t *out);
int parse_udp(const uint8_t *data, udp_pkt_t *out);
int parse_icmp(const uint8_t *data, icmp_pkt_t *out);

#endif // INCLUDE_PARSER_H_
