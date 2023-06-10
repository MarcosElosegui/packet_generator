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
#include "./includes/udp_server.h"
#include "./includes/udp.h"

#define BUFFER_LEN 4096

int nullByte(char* str);

void udp_server(int port) {
    // Crear socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket() ha fallado");
        exit(EXIT_FAILURE);
    }
    
    // anclar socket al puerto especificado
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() ha fallado");
        exit(EXIT_FAILURE);
    }
    
    printf("Escuchando en el puerto %d...\n", port);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        char buffer[BUFFER_LEN];
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &client_addr_len);
        if (recv_len < 0) {
            perror("recvfrom() ha fallado");
            exit(EXIT_FAILURE);
        }
        char *source_ip = inet_ntoa(client_addr.sin_addr);
        int source_port = ntohs(client_addr.sin_port);
        char client_ip[INET_ADDRSTRLEN];
	    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        if(port == 54){
            printf("Datagrama DNS recibido\n");
            printf("Origen del datagrama %s:%d\n", source_ip, source_port);
            printf("Tamaño del datagrama %zd\n", recv_len);
            printf("Payload del datagrama:\n");
            printf("Header DNS:\n");
            dns_header* header = (dns_header*) (buffer);
            printf("\tIdentificador DNS: 0x%04X\n", ntohs(header->id));
            printf("\tRecursion de la consulta: %hu\n", header->rd);
            printf("\tNumero de consultas: %hu\n", ntohs(header->qdcount));
            printf("Pregunta DNS:\n");
            int dom_index = nullByte(buffer + sizeof(dns_header));
            dns_question* question = (dns_question*) (buffer + sizeof(dns_header) + dom_index + 1);
            char dominio[dom_index];
            memcpy( dominio, buffer + sizeof(dns_header), dom_index);
            printf("\tNombre: %s\n", dominio);
            printf("\tTipo de consulta: %hu", ntohs(question->qtype));
            if(ntohs(question->qtype) == 255){
                printf(", ANY, peticion de todos los registros del dominio\n");
            } else {
                printf("\n");
            }
            printf("\tClase de consulta: %hu, IN", ntohs(question->qclass));
            printf("\n");
        } else if (port == 1900){
            printf("Datagrama SSDP recibido\n");
            printf("Origen del datagrama %s:%d\n", source_ip, source_port);
            printf("Tamaño del datagrama %zd\n", recv_len);
            printf("Payload del datagrama: \n%s\n\n", buffer);
        } else if (port == 11211){
            printf("Datagrama MEMCACHE recibido\n");
            printf("Origen del datagrama %s:%d\n", source_ip, source_port);
            printf("Tamaño del datagrama %zd\n", recv_len);
            printf("Payload del datagrama: \n%s\n", buffer);
        } else if (port == 123){
            printf("Datagrama NTP recibido\n");
            printf("Origen del datagrama %s:%d\n", source_ip, source_port);
            printf("Tamaño del datagrama %zd\n", recv_len);
            printf("Payload del datagrama: \n");
            int version = (buffer[0] >> 3) & 0x07;
            int codigo_peticion = buffer[3];
            printf("\tVersion NTP: %d\n", version);
            printf("\tCodigo de peticion: %d, ", codigo_peticion);
            if(codigo_peticion == 42){
                printf("MON_GETLIST_1\n");
            } else {
                printf("\n");
            }
        }else {
            printf("Datagrama UDP recibido\n");
            printf("Origen del datagrama %s:%d\n", source_ip, source_port);
            printf("Tamaño del datagrama %zd\n", recv_len);
            printf("Payload del datagrama: \n%s\n", buffer);
        }
    }
    
    // Cerrar socket
    close(sockfd);
}

int nullByte(char* str){
    int index = 0;
    while (1) {
        if (str[index] == '\0') {
            return index;
        }
        index++;
    }
    return 0;
}