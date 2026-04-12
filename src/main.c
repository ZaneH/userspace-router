#include "../include/packet.h"
#include "../include/parser.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char *filename = "./captures/google-hn.pcap";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(filename, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
    return 2;
  }

  struct pcap_pkthdr header;
  const u_char *packet;

  packet = pcap_next(handle, &header);
  printf("Jacked a packet with length of [%d]\n", header.len);

  const uint8_t *eth = packet;
  uint16_t ethertype = (eth[12] << 8) | eth[13];

  if (ethertype != 0x0800) {
    return 1;
  }

  const uint8_t *ip = packet + 14;

  IPHeader parsed;
  parse_ipv4(ip, header.len - 14, &parsed);

  printf("Version: %d\n", parsed.version);
  printf("IHL: %d\n", parsed.ihl);
  printf("Identification: %d\n", parsed.identification);

  pcap_close(handle);

  return 0;
}
