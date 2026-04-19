#include "../include/parser.h"
#include "../include/routing.h"
#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    return 2;
  }

  router_t router;
  router_create(&router, ip_from_bytes(10, 0, 0, 1),
                ip_from_bytes(255, 0, 0, 0),
                mac_from_bytes(100, 101, 102, 103, 104, 105));

  char *filename = filename = argv[1];
  int result = read_parse_pcap_file(filename);
  if (result != 0) {
    fprintf(stderr, "Failed to parse file (%d): %s\n", result, filename);
    return result;
  }

  return 0;
}
