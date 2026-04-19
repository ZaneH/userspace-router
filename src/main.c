#include "../include/parser.h"
#include "../include/routing.h"
#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    return 2;
  }

  // TODO: Create a cleaner interface for configuring a router. Maybe create
  // separate functions for each config.
  router_interface_t my_network_if = {.id = 42};
  routing_table_entry_t my_network = {.network = ip_from_bytes(10, 0, 0, 0),
                                      .nw_prefix_len =
                                          ip_from_bytes(255, 0, 0, 0),
                                      my_network_if};
  routing_table_entry_t *rt_entries[1] = {&my_network};

  router_t router;
  router_create(&router, ip_from_bytes(10, 0, 0, 1),
                ip_from_bytes(255, 0, 0, 0),
                mac_from_bytes(100, 101, 102, 103, 104, 105), rt_entries);
  router.routing_table_len = 1;

  char *filename = filename = argv[1];
  int result = read_parse_pcap_file(filename);
  if (result != 0) {
    fprintf(stderr, "Failed to parse file (%d): %s\n", result, filename);
    return result;
  }

  return 0;
}
