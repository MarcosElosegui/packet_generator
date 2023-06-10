#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>	//tcp header
#include <netinet/udp.h>	// udp header
#include <netinet/ip.h>	// ip_header
#include <arpa/inet.h>
#include <limits.h>
#include "./includes/icmp_server.h"
#include "./includes/icmp.h"

#define BUFFER_LEN 4096

void icmp_server(){
    // Crear socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket() ha fallado");
        exit(EXIT_FAILURE);
    }
    
    printf("Escuchando paquetes IMCP...");
    while (1) {
        char buffer[BUFFER_LEN];
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (recv_len < 0) {
            perror("recvfrom() ha fallado");
            exit(EXIT_FAILURE);
        }
        struct icmphdr *icmph = (struct icmphdr*) (buffer + sizeof(struct iphdr));
        struct iphdr *iph = (struct iphdr*) buffer;
        printf("Datagrama ICMP recibido\n");
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ip,INET_ADDRSTRLEN);
        printf("Origen del datagrama %s\n", ip);
        printf("Tamaño del datagrama %zd\n", recv_len);
        printf("Tipo de peticion: %d,", icmph->type);
        if(icmph->type == 8){
            printf("peticion echo (ping)\n");
        } else {
            printf("\n");
        }
        printf("Identificador de peticion: %d\n", ntohs(icmph->un.echo.id));
        printf("Numero de sequencia: %d\n\n", ntohs(icmph->un.echo.sequence));
    }
    
    // Cerrar socket
    close(sockfd);
}