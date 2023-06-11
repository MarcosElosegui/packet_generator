#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DATAGRAM_LEN 4096
#define IP_LENGTH 16
#define MAX_IP 255

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t prt_length;
};

unsigned short csum(unsigned short *ptr,int nbytes);

void generador_ip(char* ip_addr, char* subnet_mask);

int host_addr(struct sockaddr_in *h_addr, char *addr, int port);

#endif