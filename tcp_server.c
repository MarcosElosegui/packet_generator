#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "./includes/tcp_server.h"

#define BUFFER 1024

int tcp_server(int port) {
    int sockfd, newsockfd;
    struct sockaddr_in server_addr, client_addr;
    int addrlen = sizeof(client_addr);
    char buffer[BUFFER] = {0};
    char *hello = "Hello from server";
    
    // Crear socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("%d", sockfd);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Direccion servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Anclar socket a la direccion del servidor
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for incoming connections
    if (listen(sockfd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    //newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addrlen);
    printf("Escuchando en el puerto %d...\n", port);
    while(1){
        newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addrlen);

        printf("no llega ni pa dios");

        if (newsockfd < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        ssize_t bytes_received;
        while ((bytes_received = recv(newsockfd, buffer, BUFFER, 0)) > 0) {
            printf("Received %zd bytes: %s\n", bytes_received, buffer);
            memset(buffer, 0, sizeof(buffer));
        }
    }
    
    printf("Received message from client: %s\n", buffer);
    
    // Send data to client
    int bytes_sent = send(newsockfd, hello, strlen(hello), 0);
    if (bytes_sent < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Message sent to client\n");
    close(newsockfd);
    close(sockfd);
    
    return 0;
}