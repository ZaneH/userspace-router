#ifndef INCLUDE_ROUTING_H_
#define INCLUDE_ROUTING_H_

#include "identifiers.h"

typedef struct {
} router_interface_t;

typedef struct {
  /// IP address configured for this router
  ip_address_t ip;
  /// Associates known IP addresses with their MAC address
  void *arp_table;
  /// Known networks to route packets to
  void *routing_table;
  /// Packets with destinations not known to this router are forwarded to the
  /// default route
  router_interface_t *default_route;
  /// Identifies the network and host bits
  subnet_mask_t subnet_mask;
  /// Unique identifier sometimes referred to as the physical address
  mac_address_t mac_address;
} router_t;

void router_create(router_t *r, ip_address_t ip, subnet_mask_t subnet_mask,
                   mac_address_t mac);

#endif // INCLUDE_ROUTING_H_
