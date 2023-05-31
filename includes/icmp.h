#ifndef ICMP_H
#define ICMP_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "checksum.h"

#define DATAGRAM_LEN 4096

void icmp_flood(int sock, char* src, char* dst, int puerto);

#endif