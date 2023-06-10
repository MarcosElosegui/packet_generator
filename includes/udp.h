#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>	//tcp header
#include <netinet/udp.h>	// udp header
#include <netinet/ip.h>	// ip_header
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DATAGRAM_LEN 4096
#define IP_LENGTH 16
#define MAX_IP 255

typedef struct {
    char ip[IP_LENGTH];
} ipArray;

// header DNS
typedef struct {
    unsigned short id;
    unsigned char rd:1;
    unsigned char tc:1;
    unsigned char aa:1;
    unsigned char opcode:4;
    unsigned char qr:1;
    unsigned char rcode:4;
    unsigned char z:1;
    unsigned char ra:1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header;

// pregunta DNS
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} dns_question;

ipArray* generador_ip(char* ip_addr, char* subnet_mask);

void udp_datagram(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len, char* mensaje);

void udp(int sockfd, char* destino, char* addr_src, int puerto);

void udp_flood(int sockfd, char* src, char* dst, int puerto, char* mensaje);

void ssdp(int sockfd, char* src);

void udp_dns(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len);

void memcached(int sockfd, char* addr_src);

void ntp_amp(int sockfd, char* addr_src);

void dns_amp(int sockfd, char* destino, char* addr_src, int puerto);

#endif