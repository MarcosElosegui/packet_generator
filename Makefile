OBJECTS := packet_generator.o
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=gnu11
TARGET = packet_generator
LIBS = 

all: $(TARGET)

packet_generator.o: packet_generator.c

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	$(RM) $(OBJECTS) $(TARGET)