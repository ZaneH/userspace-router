#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  char *filename = "./captures/google-hn.pcap";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(filename, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
    return (2);
  }

  struct pcap_pkthdr header;
  const u_char *packet;
  packet = pcap_next(handle, &header);
  printf("Jacked a packet with length of [%d]\n", header.len);

  pcap_close(handle);

  return 0;
}
