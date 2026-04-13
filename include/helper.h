#ifndef INCLUDE_HELPER_H_
#define INCLUDE_HELPER_H_

#include "packet.h"
#include <stddef.h>
#include <stdint.h>

void print_mac(const uint8_t mac[6]);
void print_payload(const uint8_t *data, size_t len);

void print_ethframe(const EthernetFrame *hdr);
void print_ipv4(const IPHeader *hdr);
void print_tcp(const TCPHeader *hdr);
void print_udp(const UDPHeader *hdr);

#endif // INCLUDE_HELPER_H_
