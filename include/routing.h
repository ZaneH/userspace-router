#ifndef INCLUDE_ROUTING_H_
#define INCLUDE_ROUTING_H_

#include "identifiers.h"
#include "packet.h"
#include "shared_queue.h"
#include <stddef.h>

typedef struct {
  /// A unique identifier for the interface
  uint16_t id;
} router_interface_t;

typedef struct {
  /// The network IP (e.g. 192.168.0.0, 10.0.0.0)
  ip_address_t network;
  /// Significant bits for matching the network IP
  subnet_mask_t nw_prefix_len;
  /// Interface to route packets to when matched
  router_interface_t target;
} routing_table_entry_t;

typedef struct {
  /// Logical address of host
  ip_address_t host_ip;
  /// Physical address of host
  mac_address_t host_mac;
} arp_table_entry_t;

typedef routing_table_entry_t **routing_table_t;

typedef struct {
  /// IP address configured for this router
  ip_address_t ip;
  /// Associates known IP addresses with their MAC address
  arp_table_entry_t **arp_table;
  size_t arp_table_len;
  /// Known networks to route packets to
  routing_table_t routing_table;
  size_t routing_table_len;
  /// Packets with destination networks not known to this router are forwarded
  /// to the default route
  router_interface_t *default_route;
  /// Identifies the network and host bits
  subnet_mask_t subnet_mask;
  /// Physical address of router
  mac_address_t mac_address;
  /// FIFO queue for reading/parsing packets
  shared_queue_t read_parse_queue;
  /// FIFO queue for forwarding packets
  shared_queue_t forwarding_queue;
} router_t;

void router_create(router_t *r, ip_address_t ip, subnet_mask_t subnet_mask,
                   mac_address_t mac, routing_table_t routing_table,
                   size_t routing_table_len);
void router_destroy(router_t *r);
int router_process_packet(const router_t *r, parsed_packet_t *pkt);

#endif // INCLUDE_ROUTING_H_
