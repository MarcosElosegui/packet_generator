#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "./includes/tcp_server.h"
#include "./includes/udp_server.h"

int main(int argc, char *argv[]) 
{
    if (argc != 3) {
        fprintf(stderr, "Server usage: sudo %s <protocolo> <puerto>\n", argv[0]);
        exit(1);
    }

    if(strcmp(argv[1],"udp")==0){
        udp_server(atoi(argv[2]));
    } else if(strcmp(argv[1],"tcp")==0) {
        tcp_server(atoi(argv[2]));
    }
    return 0; 
}