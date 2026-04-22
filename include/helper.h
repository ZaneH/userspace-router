#ifndef INCLUDE_HELPER_H_
#define INCLUDE_HELPER_H_

#include "identifiers.h"
#include "packet.h"
#include "parser.h"
#include <stddef.h>
#include <stdint.h>

void print_ip(ip_address_t ip);
void print_mac(const uint8_t mac[6]);
void print_payload(const uint8_t *data, size_t len);

void print_ethframe(const ethernet_frame_t *frame);
void print_ipv4(const ipv4_header_t *hdr);
void print_tcp(const tcp_pkt_t *pkt);
void print_udp(const udp_pkt_t *pkt);

#endif // INCLUDE_HELPER_H_
