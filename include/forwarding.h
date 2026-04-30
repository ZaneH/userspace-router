#ifndef INCLUDE_FORWARDING_H_
#define INCLUDE_FORWARDING_H_

#include "helper.h"
#include "routing.h"

void forward_packet(router_interface_t *ifce, parsed_packet_t *pkt);

#endif // INCLUDE_FORWARDING_H_
