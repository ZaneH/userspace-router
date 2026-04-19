#include "../include/parser.h"
#include "../include/helper.h"
#include "../include/packet.h"
#include "../include/ring_buffer.h"
#include "../include/shared_queue.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  printf("Read a packet with length of [%d]\n", header->len);
  shared_queue_t *q = (shared_queue_t *)args;

  const uint8_t *eth = packet;

  ethernet_frame_t ef;
  parse_ethframe(eth, &ef);
  print_ethframe(&ef);

  if (ef.type != 0x0800)
    return;

  const uint8_t *ipv4_data = packet + SIZE_ETHERNET;

  ipv4_header_t ipv4;
  parse_ipv4(ipv4_data, header->len - SIZE_ETHERNET, &ipv4);
  print_ipv4(&ipv4);

  if (ipv4.protocol == IPPROTO_TCP) {
    const uint8_t *tcp_data = ipv4_data + ipv4.ihl * 4;

    tcp_pkt_t tcp;
    parse_tcp(tcp_data, ipv4.total_length, &tcp);
    print_tcp(&tcp);

    parsed_packet_t *parsed = malloc(sizeof(parsed_packet_t));
    parsed->type = PACKET_TYPE_TCP;
    parsed->tcp = tcp;

    pthread_mutex_lock(&q->mutex);
    if (!ring_buffer_full(q->rb)) {
      printf("Placing value in queue\n");
      ring_buffer_push(q->rb, (uintptr_t *)&parsed);
    } else {
      printf("Queue is full\n");
    }
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);

    // TODO: Use pre-allocated pool to reduce mallocs in hot-path
    free(parsed);
    free(tcp.payload);
  } else if (ipv4.protocol == IPPROTO_UDP) {
    const uint8_t *udp_data = ipv4_data + ipv4.ihl * 4;

    udp_pkt_t udp;
    parse_udp(udp_data, &udp);
    print_udp(&udp);

    parsed_packet_t *parsed = malloc(sizeof(parsed_packet_t));
    parsed->type = PACKET_TYPE_UDP;
    parsed->udp = udp;

    pthread_mutex_lock(&q->mutex);
    if (!ring_buffer_full(q->rb)) {
      printf("Placing value in queue\n");
      ring_buffer_push(q->rb, (uintptr_t *)&parsed);
    } else {
      printf("Queue is full\n");
    }
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);

    // TODO: Use pre-allocated pool to reduce mallocs in hot-path
    free(parsed);
    free(udp.payload);
  }
}

typedef struct {
  const char *filename;
  shared_queue_t *queue;
} read_packets_args_t;

typedef struct {
  shared_queue_t *queue;
} parse_packets_args_t;

void *start_pcap_reader(void *arg) {
  char errbuf[PCAP_ERRBUF_SIZE];

  read_packets_args_t *args = (read_packets_args_t *)arg;
  const char *filename = args->filename;
  shared_queue_t *q = args->queue;
  free(args);

  pcap_t *handle = pcap_open_offline(filename, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
  }

  pcap_loop(handle, -1, got_packet, (u_char *)q);

  pthread_mutex_lock(&q->mutex);
  q->producer_finished = true;
  pthread_cond_signal(&q->not_empty);
  pthread_mutex_unlock(&q->mutex);

  pcap_close(handle);

  return NULL;
}

void *start_pcap_parser(void *arg) {
  parse_packets_args_t *args = (parse_packets_args_t *)arg;
  shared_queue_t *q = args->queue;
  free(arg);

  while (true) {
    pthread_mutex_lock(&q->mutex);
    while (ring_buffer_empty(q->rb) && !q->producer_finished)
      pthread_cond_wait(&q->not_empty, &q->mutex);

    if (ring_buffer_empty(q->rb) && q->producer_finished) {
      pthread_mutex_unlock(&q->mutex);
      break;
    }

    uintptr_t result;
    ring_buffer_pop(q->rb, &result);
    pthread_mutex_unlock(&q->mutex);
    printf("Got this from queue: %p\n", &result);
  }

  return NULL;
}

int read_parse_pcap_file(const char *filename) {
  pthread_t reader_thread;
  pthread_t parser_thread;

  ring_buffer_t rb = ring_buffer_create(10);
  shared_queue_t q;
  pthread_mutex_t q_mutex;
  pthread_cond_t non_empty_cond;
  shared_queue_create(&q, &rb, &q_mutex, &non_empty_cond);

  read_packets_args_t *reader_args = malloc(sizeof(read_packets_args_t));
  reader_args->filename = filename;
  reader_args->queue = &q;

  parse_packets_args_t *parser_args = malloc(sizeof(parse_packets_args_t));
  parser_args->queue = &q;

  if (pthread_create(&reader_thread, NULL, start_pcap_reader, reader_args) !=
      0) {
    free(reader_args);
    free(rb.buffer);
    return 2;
  }

  if (pthread_create(&parser_thread, NULL, start_pcap_parser, parser_args) !=
      0) {
    free(parser_args);
    free(rb.buffer);
    return 2;
  }

  pthread_join(reader_thread, NULL);
  pthread_join(parser_thread, NULL);

  free(rb.buffer);

  return 0;
}

int parse_ethframe(const uint8_t *data, ethernet_frame_t *out) {
  memcpy(out->dst, data, 6);
  memcpy(out->src, data + 6, 6);
  out->type = data[12] << 8 | data[13];
  return 0;
}

int parse_ipv4(const uint8_t *data, size_t len, ipv4_header_t *out) {
  if (len < 20)
    return -1;

  uint8_t vhl = data[0];
  out->version = vhl >> 4;
  out->ihl = vhl & 0x0F;

  uint8_t ds = data[1];
  out->dscp = ds >> 2;
  out->ecn = ds & 0x03;

  out->total_length = data[2] << 8 | data[3];
  out->identification = data[4] << 8 | data[5];

  uint16_t flags_fo = data[6] << 8 | data[7];
  out->flags = flags_fo >> 13;
  out->fragment_offset = flags_fo & 0x1FFF;

  out->ttl = data[8];
  out->protocol = data[9];
  out->checksum = data[10] << 8 | data[11];
  out->src = data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15];
  out->dst = data[16] << 24 | data[17] << 16 | data[18] << 8 | data[19];

  return 0;
}

int parse_tcp(const uint8_t *data, size_t total_length, tcp_pkt_t *out) {
  out->src_port = data[0] << 8 | data[1];
  out->dst_port = data[2] << 8 | data[3];
  out->seq_number = 1;
  out->seq_number = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
  out->ack_number = data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11];

  uint16_t len_flags = data[12] << 8 | data[13];
  out->hdr_len = len_flags >> 12;
  out->flags = len_flags & 0x0FFF;

  out->window = data[14] << 8 | data[15];
  out->checksum = data[16] << 8 | data[17];
  out->urgent_pointer = data[18] << 8 | data[19];

  size_t payload_size = total_length - SIZE_TCP - (out->hdr_len * 4);
  out->payload = malloc(payload_size);
  out->payload_size = payload_size;
  memcpy(out->payload, data + 32, payload_size);
  return 0;
}

int parse_udp(const uint8_t *data, udp_pkt_t *out) {
  out->src_port = data[0] << 8 | data[1];
  out->dst_port = data[2] << 8 | data[3];
  out->length = data[4] << 8 | data[5];
  out->checksum = data[6] << 8 | data[7];
  out->payload = malloc(out->length);
  memcpy(out->payload, data + SIZE_UDP, out->length - SIZE_UDP);
  return 0;
}
