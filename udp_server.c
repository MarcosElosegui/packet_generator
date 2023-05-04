#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include "./includes/udp_server.h"

void hex_to_text(char* hex_string);

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
        char buffer[64];
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &client_addr_len);
        if (recv_len < 0) {
            perror("recvfrom() ha fallado");
            exit(EXIT_FAILURE);
        }
        char *source_ip = inet_ntoa(client_addr.sin_addr);
        int source_port = ntohs(client_addr.sin_port);
        char client_ip[INET_ADDRSTRLEN];
	    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Origen del datagrama %s:%d\n", source_ip, source_port);
        printf("Tamaño del datagrama %zd\n", recv_len);
        printf("Payload del datagrama:\n");
        hex_to_text(buffer);
        printf("%s", buffer);
        printf("\n");
        if (recv_len % 16 != 0) {
            printf("\n");
        }
    }
    
    // Cerrar socket
    close(sockfd);
}

void hex_to_text(char* hex_string) {
    int hex_len = strlen(hex_string);
    if (hex_len % 2 != 0) {
        printf("Invalid hexadecimal string\n");
        return;
    }
    int text_len = hex_len / 2;
    char* text_string = (char*) malloc(text_len + 1);
    text_string[text_len] = '\0';

    for (int i = 0; i < hex_len; i += 2) {
        char hex_char[3] = {hex_string[i], hex_string[i+1], '\0'};
        int hex_val = (int) strtol(hex_char, NULL, 16);
        text_string[i/2] = (char) hex_val;
    }
    hex_string = text_string;
    free(text_string);
}