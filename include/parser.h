#ifndef INCLUDE_PARSER_H_
#define INCLUDE_PARSER_H_

#include "./packet.h"
#include <stddef.h>
#include <stdint.h>

extern const int kIPHeaderSize;
extern const int kTCPHeaderSize;
extern const int kUDPHeaderSize;

int parse_ethframe(const uint8_t *data, EthernetFrame *out);
int parse_ipv4(const uint8_t *data, size_t len, IPHeader *out);
int parse_tcp(const uint8_t *data, size_t total_length, TCPHeader *out);
int parse_udp(const uint8_t *data, UDPHeader *out);

#endif // INCLUDE_PARSER_H_
