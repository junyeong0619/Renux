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
    LDFLAGS         = -Wl,-z,relro,-z,now
    OPENSSL_CFLAGS  =
    OPENSSL_LDFLAGS =
else
    LDFLAGS         =
    OPENSSL_PREFIX  := $(shell brew --prefix openssl 2>/dev/null)
    OPENSSL_CFLAGS  := $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include,)
    OPENSSL_LDFLAGS := $(if $(OPENSSL_PREFIX),-L$(OPENSSL_PREFIX)/lib,)
endif

CFLAGS   += $(OPENSSL_CFLAGS)
CXXFLAGS += $(OPENSSL_CFLAGS)

# ─────────────────────────────────────────────────────────────────────
#  eBPF 빌드 파이프라인 (Linux 전용)
#
#  의존 패키지: clang llvm libbpf-dev linux-headers-generic
#               linux-tools-generic libelf-dev zlib1g-dev
# ─────────────────────────────────────────────────────────────────────
ifeq ($(UNAME_S),Linux)
    BPF_ARCH   := $(shell uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/')
    VMLINUX_H   = monitoring/vmlinux.h
    EBPF_OBJ    = monitoring/renux.bpf.o
    EBPF_SKEL   = monitoring/renux.skel.h

    TARGETS = server_e client_e renux renux_master

    # 1. vmlinux.h 생성 (BTF from running kernel)
    $(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

    # 2. eBPF 오브젝트 컴파일
    $(EBPF_OBJ): monitoring/renux.bpf.c monitoring/renux_event.h $(VMLINUX_H)
	clang -O2 -g -target bpf \
	    -D__BPF_PROGRAM__ \
	    -D__TARGET_ARCH_$(BPF_ARCH) \
	    -I monitoring/ \
	    -c $< -o $@

    # 3. skeleton 헤더 생성
    $(EBPF_SKEL): $(EBPF_OBJ)
	bpftool gen skeleton $< name renux > $@

    # renux: eBPF skeleton 의존
    renux: monitoring/monitor.cpp utils/ssl_utils.c $(EBPF_SKEL)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) \
	    -I monitoring/ \
	    -o $@ monitoring/monitor.cpp utils/ssl_utils.c \
	    -lssl -lcrypto -lbpf -lelf -lz

    clean:
	rm -f $(TARGETS) $(EBPF_OBJ) $(EBPF_SKEL) $(VMLINUX_H)

else
    # macOS: renux는 Linux 전용이므로 빌드 대상에서 제외
    TARGETS = server_e client_e renux_master

    renux:
	@echo "renux (monitoring agent) is Linux-only. Skipping."

    clean:
	rm -f $(TARGETS)
endif

# ─────────────────────────────────────────────────────────────────────
#  공통 타겟
# ─────────────────────────────────────────────────────────────────────

all: $(TARGETS)

server_e: server/server.c server/tui.c server/service.c \
          utils/ssl_utils.c utils/log.c utils/exec_utils.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lncurses -lssl -lcrypto -lcap

client_e: client/client.c client/tui.c \
          utils/ssl_utils.c utils/log.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lncurses -lpthread -lssl -lcrypto

renux_master: monitoring/master.cpp utils/ssl_utils.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ -lssl -lcrypto -lncurses

.PHONY: all clean renux
