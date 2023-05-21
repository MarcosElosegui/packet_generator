#ifndef ICMP_H
#define ICMP_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>	//tcp header
#include <netinet/udp.h>	// udp header
#include <netinet/ip.h>	// ip_header
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "checksum.h"

#define DATAGRAM_LEN 4096

void icmp_flood(int sock, char* src, char* dst, int puerto);

#endif