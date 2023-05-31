#ifndef TCP_H
#define TCP_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "checksum.h"

#define PACKET_LEN 4096
#define OPT_SIZE 20

int host_addr(struct sockaddr_in *h_addr, char *addr, int port);

void tcp_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** packet_ret, int* packet_len);

int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst);

void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len);

void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack);

int syn_flood(int sockfd, char *address_dst, char *address_src, int port);

#endif