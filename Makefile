CC = gcc

CFLAGS = -g -Wall

TARGETS = server_e client_e

all: $(TARGETS)


server_e: server/server.c server/tui.c server/service.c
	$(CC) $(CFLAGS) -o server_e server/server.c server/tui.c server/service.c -lncurses


client_e: client/client.c client/tui.c
	$(CC) $(CFLAGS) -o client_e client/client.c client/tui.c -lncurses -lpthread

clean:
	rm -f $(TARGETS)

.PHONY: all clean