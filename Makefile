CC  = gcc
CXX = g++

# OS 감지 (macOS / Linux 분기)
UNAME_S := $(shell uname -s)

# 공통 보안 컴파일 플래그
CFLAGS   = -Wall -O2 -std=gnu99 -D_XOPEN_SOURCE=700 \
           -fstack-protector-all -D_FORTIFY_SOURCE=2 \
           -Wformat -Wformat-security

CXXFLAGS = -std=c++17 -O2 \
           -fstack-protector-all -D_FORTIFY_SOURCE=2 \
           -Wformat -Wformat-security

# Linux 전용 링커 하드닝 플래그 (macOS의 ld는 미지원)
# macOS: Homebrew OpenSSL 경로 추가 (brew install openssl)
ifeq ($(UNAME_S),Linux)
    LDFLAGS   = -Wl,-z,relro,-z,now
    OPENSSL_CFLAGS  =
    OPENSSL_LDFLAGS =
else
    LDFLAGS   =
    OPENSSL_PREFIX  := $(shell brew --prefix openssl 2>/dev/null)
    OPENSSL_CFLAGS  := $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include,)
    OPENSSL_LDFLAGS := $(if $(OPENSSL_PREFIX),-L$(OPENSSL_PREFIX)/lib,)
endif

CFLAGS   += $(OPENSSL_CFLAGS)
CXXFLAGS += $(OPENSSL_CFLAGS)

TARGETS = server_e client_e renux renux_master

all: $(TARGETS)

server_e: server/server.c server/tui.c server/service.c \
          utils/ssl_utils.c utils/log.c utils/exec_utils.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lncurses -lssl -lcrypto -lcap

client_e: client/client.c client/tui.c \
          utils/ssl_utils.c utils/log.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lncurses -lpthread -lssl -lcrypto

renux: monitoring/monitor.cpp utils/ssl_utils.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lssl -lcrypto

renux_master: monitoring/master.cpp utils/ssl_utils.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lssl -lcrypto

clean:
	rm -f $(TARGETS)

.PHONY: all clean
