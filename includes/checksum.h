#ifndef PSEUDOHEADER_H
#define PSEUDOHEADER_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t prt_length;
};

unsigned short csum(unsigned short *ptr,int nbytes);

#endif /* PSEUDOHEADER_H */