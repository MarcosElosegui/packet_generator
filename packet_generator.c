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

	if (argc != 6) {
        fprintf(stderr, "Packet generator usage: sudo %s <dest_addr> <src_addr> <subnet_mask> <dest_port> <protocol>\n", argv[0]);
        exit(1);
    }

    char *ip_addr = argv[2];
    char *subnet_mask = argv[3];
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
	if(strcmp(argv[5], "udp") == 0){
		sockfd = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
	} else if((strcmp(argv[5], "tcp") == 0) || (strcmp(argv[5], "syn_flood") == 0)){
		sockfd = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	}

    if(sockfd == -1){
        perror("Ha habido un problema al crear el socket");
        exit(1);
    }

	//IP_HDRINCL indicamos al kernel que los headers se incluyen en el paquete
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}
	
	if (setsockopt (sockfd, SOL_SOCKET, SO_DEBUG, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    for(i = 0; i < num_addrs; i++){


		// direccion IP de destino
		struct sockaddr_in daddr;
		daddr.sin_family = AF_INET;
		daddr.sin_port = htons(atoi(argv[4]));
		if (inet_pton(AF_INET, argv[1], &daddr.sin_addr) != 1)
		{
			printf("destination IP configuration failed\n");
			return 1;
		}

        struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;
        struct in_addr aux;
        aux.s_addr = htonl(curr_addr.s_addr);
        char *addr_src = inet_ntoa(aux);

		// direccion IP de origen
		struct sockaddr_in saddr;
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(rand() % 65535); // random client port
		if (inet_pton(AF_INET, addr_src, &saddr.sin_addr) != 1)
		{
			printf("source IP configuration failed\n");
			return 1;
		}

        /*struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;*/

		if(strcmp(argv[5], "udp") == 0){

			char* datagram;
			int datagram_len;
			udp_datagram(&saddr, &daddr, &datagram, &datagram_len);
			
			if(sendto (sockfd, datagram, datagram_len ,	0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
			{
				perror("No se ha podido enviar el datagrama");
			} else {
				printf ("Datagrama enviado. Tamaño : %d \n" , datagram_len);
			}
		} else if((strcmp(argv[5], "tcp") == 0)){

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
		} else if((strcmp(argv[5], "syn_flood") == 0)){
			syn_flood(sockfd, argv[1], argv[2], atoi(argv[4]));
		}
        sleep(1);
    }
}