#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "./includes/tcp_server.h"
#include "./includes/udp_server.h"

int main(int argc, char *argv[]) 
{
    char *protocolo, *puerto;
    int j;

    for (j = 1; j < argc; j+=2) {
        if (strcmp(argv[j], "-p") == 0) {
			if (j + 1 < argc) {
				printf("%d", strncmp(argv[j+1], "-", 1));
				if(strncmp(argv[j+1], "-", 1)){
					puerto = argv[j + 1];
				} else {
					printf("Error: -p necesita un argumento.\n");
				}
            } else {
                printf("Error: -p necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-prt") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					protocolo = argv[j + 1];
				} else {
					printf("Error: -prt necesita un argumento.\n");
				}
            } else {
                printf("Error: -prt necesita un argumento.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Server usage: sudo %s <protocolo> <puerto>\n", argv[0]);
        	return 1;
        }
    }

    if(strcmp(protocolo,"udp")==0){
        udp_server(atoi(puerto));
    } else if(strcmp(protocolo,"tcp")==0) {
        tcp_server(atoi(puerto));
    }
    return 0; 
}