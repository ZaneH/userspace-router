#include "../include/routing.h"
#include "../include/forwarding.h"
#include "../include/helper.h"
#include <stdbool.h>
#include <stdlib.h>

void router_create(router_t *r, ip_address_t ip, subnet_mask_t subnet_mask,
                   mac_address_t mac, routing_table_t routing_table,
                   size_t routing_table_len) {
  r->ip = ip;
  r->subnet_mask = subnet_mask;
  r->mac_address = mac;
  r->routing_table = routing_table;
  r->routing_table_len = routing_table_len;

  shared_queue_create(&r->read_parse_queue, 10);
  shared_queue_create(&r->forwarding_queue, 10);
}

void router_destroy(router_t *r) {
  shared_queue_destroy(&r->read_parse_queue);
  shared_queue_destroy(&r->forwarding_queue);
}

routing_table_entry_t *lookup_route(ip_address_t dst,
                                    const routing_table_t table, size_t size) {
  for (int i = 0; i < size; i++) {
    ip_address_t masked_dst = dst & table[i]->nw_prefix_len;
    ip_address_t candidate = table[i]->network & table[i]->nw_prefix_len;
    if (masked_dst == candidate) {
      return table[i];
    }
  }

  return NULL;
}

int router_process_packet(const router_t *r, parsed_packet_t *pkt) {
  routing_table_entry_t *route =
      lookup_route(pkt->ip_hdr.dst, r->routing_table, r->routing_table_len);
  if (route != NULL) {
    printf("Found a valid route for dst: ");
    print_ip(pkt->ip_hdr.dst);
    printf(" => ");
    print_ip(route->network);
    printf(" on interface (%d)\n", route->target.id);
    forward_packet(&route->target, pkt);
  }

  print_ipv4(&pkt->ip_hdr);
  print_ethframe(&pkt->eth_frame);
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

  return 0;
}
