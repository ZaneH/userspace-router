#include "../include/forwarding.h"

void forward_packet(router_interface_t *out_ifce, parsed_packet_t *pkt) {
  pkt->ip_hdr.ttl--;
  // TODO: Forward packet
}
