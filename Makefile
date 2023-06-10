CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=gnu11
TARGET = packet_generator
STARGET = server

LIBS =
# define the C source files
SRCS = packet_generator.c tcp.c udp.c checksum.c icmp.c
SSRCS = server.c udp_server.c tcp_server.c icmp_server.c

all: cliente server

cliente: $(SRCS) 
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) -pthread -g

server: $(SSRCS)
	$(CC) $(CFLAGS) -o $(STARGET) $(SSRCS)

clean:
	$(RM) *.o *~ $(TARGET) $(SERV_TARGET)