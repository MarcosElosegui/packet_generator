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
#include "./includes/checksum.h"
#include "./includes/udp.h"

#define DATAGRAM_LEN 4096

void udp_datagram(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len, char* mensaje){

    char *data , *pseudogram;

    char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

    //IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	struct pseudo_header psh;

	// Payload del paquete
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data , mensaje);
	
	// IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data); //Tamaño de todo el paquete
	iph->id = htonl(rand() % 78123);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
    // header udp
	udph->source = src->sin_port;
	udph->dest = dst->sin_port;
	udph->len = htons(sizeof(struct udphdr) + strlen(data));
	udph->check = 0;
	
	//UDP checksum
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.prt_length = htons(sizeof(struct udphdr) + strlen(data));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);

    *datagram_ret = datagram;
	*datagram_len = iph->tot_len;
	free(pseudogram);
}
