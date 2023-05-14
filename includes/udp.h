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
#include "checksum.h"

#define DATAGRAM_LEN 4096

void udp_datagram(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len, char* mensaje);

#endif