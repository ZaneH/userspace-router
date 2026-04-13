#include "../include/helper.h"
#include "../include/parser.h"
#include <stdint.h>
#include <stdio.h>

void print_mac(const uint8_t mac[6]) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void print_payload(const uint8_t *data, size_t len) {
  for (int i = 0; i < len; i++) {
    printf(i == len - 1 ? "%02x" : "%02x ", data[i]);
  };
}

void print_ethframe(const EthernetFrame *hdr) {
  printf("=== EthernetFrame ===========================\n");
  printf("Dst: ");
  print_mac(hdr->dst);
  printf("\nSrc: ");
  print_mac(hdr->src);
  printf("\nType: 0x%04x\n", hdr->type);
}

void print_ipv4(const IPHeader *hdr) {
  printf("=== IPv4 ===========================\n");
  printf("Version: %d\n", hdr->version);
  printf("IHL: %d\n", hdr->ihl);
  printf("DSCP: %d\n", hdr->dscp);
  printf("ECN: %d\n", hdr->ecn);
  printf("Total Length: %d\n", hdr->total_length);
  printf("Identification: 0x%04x\n", hdr->identification);
  printf("Flags: 0x%x\n", hdr->flags);
  printf("Fragment Offset: 0x%x\n", hdr->fragment_offset);
  printf("TTL: %d\n", hdr->ttl);
  printf("Protocol: %d\n", hdr->protocol);
  printf("Checksum: 0x%x\n", hdr->checksum);
  printf("Src: 0x%08x\n", hdr->src);
  printf("Dst: 0x%08x\n", hdr->dst);
}

void print_tcp(const TCPHeader *hdr) {
  printf("=== TCP ===========================\n");
  printf("Source Port: %d\n", hdr->src_port);
  printf("Destination Port: %d\n", hdr->dst_port);
  printf("Sequence Number (Raw): %u\n", hdr->seq_number);
  printf("Acknowledgement Number (Raw): %u\n", hdr->ack_number);
  printf("Header Length: %d\n", hdr->hdr_len);
  printf("Flags: 0x%03x\n", hdr->flags);
  printf("Window: %d\n", hdr->window);
  printf("Checksum: 0x%x\n", hdr->checksum);
  printf("Urgent Pointer: %d\n", hdr->urgent_pointer);
  printf("Options: WIP\n");
  printf("Payload:\n");
  print_payload(hdr->payload, hdr->payload_size);
  printf("\n");
}

void print_udp(const UDPHeader *hdr) {
  printf("=== UDP ===========================\n");
  printf("Source Port: %d\n", hdr->src_port);
  printf("Destination Port: %d\n", hdr->dst_port);
  printf("Length: %d\n", hdr->length);
  printf("Checksum: 0x%04x\n", hdr->checksum);
  printf("Payload:\n");
  print_payload(hdr->payload, hdr->length - SIZE_UDP);
  printf("\n");
}
