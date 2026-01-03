CC = gcc
CXX = g++

CFLAGS = -g -Wall -std=gnu99 -D_XOPEN_SOURCE=700
CXXFLAGS = -std=c++17

TARGETS = server_e client_e renux

all: $(TARGETS)

server_e: server/server.c server/tui.c server/service.c utils/ssl_utils.c
	$(CC) $(CFLAGS) -o server_e server/server.c server/tui.c server/service.c utils/ssl_utils.c utils/log.c -lncurses

client_e: client/client.c client/tui.c utils/ssl_utils.c
	$(CC) $(CFLAGS) -o client_e client/client.c client/tui.c utils/ssl_utils.c utils/log.c -lncurses -lpthread

renux: monitoring/monitor.cpp
	$(CXX) $(CXXFLAGS) -o renux monitoring/monitor.cpp

renux_master: monitoring/master.cpp
	$(CXX) $(CXXFLAGS) -o renux_master monitoring/master.cpp

clean:
	rm -f $(TARGETS)

.PHONY: all clean