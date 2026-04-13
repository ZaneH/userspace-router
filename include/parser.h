#ifndef INCLUDE_PARSER_H_
#define INCLUDE_PARSER_H_

#include "./packet.h"
#include <stddef.h>
#include <stdint.h>

#define SIZE_ETHERNET 14
#define SIZE_TCP 20
#define SIZE_UDP 8

int parse_pcap_file(const char *filename);

int parse_ethframe(const uint8_t *data, EthernetFrame *out);
int parse_ipv4(const uint8_t *data, size_t len, IPHeader *out);
int parse_tcp(const uint8_t *data, size_t total_length, TCPHeader *out);
int parse_udp(const uint8_t *data, UDPHeader *out);

#endif // INCLUDE_PARSER_H_
