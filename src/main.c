#include "../include/parser.h"
#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    return 2;
  }

  char *filename = filename = argv[1];
  int result = parse_pcap_file(filename);
  if (result != 0) {
    fprintf(stderr, "Failed to parse file (%d): %s\n", result, filename);
    return result;
  }

  return 0;
}
