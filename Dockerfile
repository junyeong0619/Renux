FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && apt-get install -y \
    gcc g++ make \
    libssl-dev libcap-dev libncurses-dev \
    openssl expect iproute2 procps net-tools \
    netcat-openbsd socat \
    clang llvm libbpf-dev \
    linux-headers-generic linux-tools-generic \
    libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /renux
COPY . .

RUN make clean && make all

# TLS 인증서 생성
RUN mkdir -p /etc/renux && \
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/renux/server.key \
        -out    /etc/renux/server.crt \
        -days 730 -nodes \
        -subj "/CN=renux-server/O=Renux" 2>/dev/null && \
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/renux/master.key \
        -out    /etc/renux/master.crt \
        -days 730 -nodes \
        -subj "/CN=renux-master/O=Renux" 2>/dev/null && \
    chmod 600 /etc/renux/*.key && chmod 644 /etc/renux/*.crt

# renux 에이전트 설정 (docker-compose에서 MASTER_IP 환경변수로 덮어씀)
RUN echo "MASTER_IP=127.0.0.1" > /etc/renux.conf && \
    echo "MASTER_PORT=9000"   >> /etc/renux.conf

# 로그 디렉토리
RUN mkdir -p /var/log && touch /var/log/renux.log
