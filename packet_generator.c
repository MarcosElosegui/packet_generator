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

unsigned short csum(unsigned short *ptr,int nbytes);
void tcp_packet(int sockfd, char *source_addr, int port, char *addr);
void udp_datagram(int sockfd, char *source_addr, int port, char *addr);

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t prt_length;
};

int main(int argc, char *argv[]){

	if (argc != 6) {
        fprintf(stderr, "Packet generator usage: sudo %s <dest_addr> <src_addr> <subnet_mask> <dest_port> <protocol>\n", argv[0]);
        exit(1);
    }

    char *ip_addr = argv[2];
    char *subnet_mask = argv[3];
    struct in_addr addr;
    struct in_addr mask;
    struct in_addr net_addr;
    struct in_addr broadcast_addr;
    uint32_t i, num_addrs;

    inet_pton(AF_INET, ip_addr, &addr);
    inet_pton(AF_INET, subnet_mask, &mask);

    net_addr.s_addr = addr.s_addr & mask.s_addr;
    broadcast_addr.s_addr = net_addr.s_addr | ~mask.s_addr;

    num_addrs = ntohl(broadcast_addr.s_addr) - ntohl(net_addr.s_addr) + 1;

	int sockfd = 0;

    //Creamos un socket RAW indica que no se generen los headers del protocolo ni el de ip
	if(strcmp(argv[5], "udp") == 0){
		sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
	} else if((strcmp(argv[5], "tcp") == 0)){
		sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
	}

    if(sockfd == -1){
        perror("Ha habido un problema al crear el socket");
        exit(1);
    }

	//IP_HDRINCL indicamos al kernel que los headers se incluyen en el paquete
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    for(i = 0; i < 1; i++){
        struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;
		if(strcmp(argv[5], "udp") == 0){
			udp_datagram(sockfd, inet_ntoa(curr_addr), atoi(argv[4]), argv[1]);
		} else if((strcmp(argv[5], "tcp") == 0)){
			tcp_packet(sockfd, inet_ntoa(curr_addr), atoi(argv[4]), argv[1]);
		}
        sleep(1);
    }
}

void tcp_packet(int sockfd, char *source_addr, int port, char *addr){
	char packet[4096] , source_ip[32] , *data , *pseudogram;
	memset (packet, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) packet;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , "Paquete custom");
	
	//some address resolution
	strcpy(source_ip , source_addr);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr (addr);
	
	//IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl (44566);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr ( source_ip );
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	
	//TCP Header
	tcph->source = htons (1234);
	tcph->dest = htons (port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	
	//TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.prt_length = htons(sizeof(struct tcphdr) + strlen(data));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);

	connect(sockfd, (struct sockaddr *)&sin, sizeof(data));
	//send(sockfd, packet, iph->tot_len, 0);
	
	if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0) 
	{
		perror("No se ha podido enviar el paquete");
	} else {
		printf ("Paquete enviado. Tamaño : %d \n" , iph->tot_len);
	}
}

void udp_datagram(int sockfd, char *source_addr, int port, char *addr){

    char datagram[4096], source_ip[32], *data , *pseudogram;
    memset(datagram, 0, 4096);

    //IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	struct sockaddr_in sin;
	struct pseudo_header psh;

	// Payload del paquete
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data , "Paquete custom");

    strcpy(source_ip , source_addr);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr (addr);
	
	// IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data); //Tamaño de todo el paquete
	iph->id = htonl(12343);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = inet_addr ( source_ip );
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
    // header udp
	udph->source = htons (1234);
	udph->dest = htons (port);
	udph->len = htons(sizeof(struct udphdr) + strlen(data));
	udph->check = 0;
	
	//UDP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.prt_length = htons(sizeof(struct udphdr) + strlen(data));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);

    if(sendto (sockfd, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        perror("No se ha podido enviar el datagrama");
    } else {
		printf ("Datagrama enviado. Tamaño : %d \n" , iph->tot_len);
	}
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}