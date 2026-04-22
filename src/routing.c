#include "../include/routing.h"
#include "../include/helper.h"
#include <stdlib.h>

void router_create(router_t *r, ip_address_t ip, subnet_mask_t subnet_mask,
                   mac_address_t mac, routing_table_t routing_table,
                   size_t routing_table_len) {
  r->ip = ip;
  r->subnet_mask = subnet_mask;
  r->mac_address = mac;
  r->routing_table = routing_table;
  r->routing_table_len = routing_table_len;
}

int router_process_packet(const router_t *r, const parsed_packet_t *pkt) {
  switch (pkt->type) {
  case PACKET_TYPE_TCP:
    print_tcp(&pkt->tcp);
    free(pkt->tcp.payload);
    break;
  case PACKET_TYPE_UDP:
    print_udp(&pkt->udp);
    free(pkt->udp.payload);
    break;
  default:
    printf("Unhandled packet type (%d)", pkt->type);
  }

  printf("Router has routing table len: %zu\n", r->routing_table_len);
  for (int i = 0; i < r->routing_table_len; i++) {
    printf("-> Route: ");
    print_ip(r->routing_table[i]->network);
    printf(" => %d\n", r->routing_table[i]->target.id);
  }

  return 0;
}
