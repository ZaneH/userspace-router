#include "../include/routing.h"

void router_create(router_t *r, ip_address_t ip, subnet_mask_t subnet_mask,
                   mac_address_t mac, routing_table_t routing_table) {
  r->ip = ip;
  r->subnet_mask = subnet_mask;
  r->mac_address = mac;
  r->routing_table = routing_table;
}
