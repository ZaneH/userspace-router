#include "../include/packet.h"
#include "../include/parser.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

void print_mac(const uint8_t mac[6]) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

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
  printf("Read a packet with length of [%d]\n", header.len);

  const uint8_t *eth = packet;

  EthernetFrame ef;
  parse_ethframe(eth, &ef);

  printf("=== EthernetFrame ===========================\n");
  printf("Dst: ");
  print_mac(ef.dst);
  printf("\nSrc: ");
  print_mac(ef.src);
  printf("\nType: 0x%04x\n", ef.type);

  if (ef.type != 0x0800)
    return 1;

  const uint8_t *ipv4_data = packet + 14;

  IPHeader ipv4;
  parse_ipv4(ipv4_data, header.len - 14, &ipv4);

  printf("=== IPv4 ===========================\n");
  printf("Version: %d\n", ipv4.version);
  printf("IHL: %d\n", ipv4.ihl);
  printf("DSCP: %d\n", ipv4.dscp);
  printf("ECN: %d\n", ipv4.ecn);
  printf("Total Length: %d\n", ipv4.total_length);
  printf("Identification: 0x%04x\n", ipv4.identification);
  printf("Flags: 0x%x\n", ipv4.flags);
  printf("Fragment Offset: 0x%x\n", ipv4.fragment_offset);
  printf("TTL: %d\n", ipv4.ttl);
  printf("Protocol: %d\n", ipv4.protocol);
  printf("Checksum: 0x%x\n", ipv4.checksum);
  printf("Src: 0x%x\n", ipv4.src);
  printf("Dst: 0x%x\n", ipv4.dst);

  pcap_close(handle);

  return 0;
}
