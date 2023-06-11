#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "./includes/helpers.h"

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

//Funcion que genera ip de los parametros dados
void generador_ip(char* ip_addr, char* subnet_mask){
	struct in_addr addr;
    struct in_addr mask;
    struct in_addr net_addr;
    struct in_addr broadcast_addr;
    uint32_t num_addrs;

	//Calculamos la cantidad de ips con la mascara proporcionada

    inet_pton(AF_INET, ip_addr, &addr);
    inet_pton(AF_INET, subnet_mask, &mask);

    net_addr.s_addr = addr.s_addr & mask.s_addr;
    broadcast_addr.s_addr = net_addr.s_addr | ~mask.s_addr;

    num_addrs = ntohl(broadcast_addr.s_addr) - ntohl(net_addr.s_addr) + 1;
	struct in_addr curr_addr;
	curr_addr.s_addr = ntohl(net_addr.s_addr) + (rand() % num_addrs);
	struct in_addr aux;
	aux.s_addr = htonl(curr_addr.s_addr);
	char *addr_src = inet_ntoa(aux);
	printf("%s\n", addr_src);
}

//Funcion que dados una direccion y un puerto crea una estructura sockaddr_in
int host_addr(struct sockaddr_in *h_addr, char *addr, int port){
	struct sockaddr_in host;
	host.sin_family = AF_INET;
	host.sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &host.sin_addr) != 1)
	{
		return 1;
	}
	*h_addr = host;
	return 0;
}