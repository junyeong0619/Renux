//
// Created by Junyeong on 2025. 9. 2..
//
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080

int main() {
    int sock = 0;
    ssize_t valread;
    struct sockaddr_in serv_addr;
    const char *hello = "Hello from client";
    char buffer[1024] = {0};

    // 1. 소켓 생성
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 2. 서버 주소 설정
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // 3. 서버에 연결
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }
    printf("서버에 연결되었습니다.\n");

    // 4. 데이터 전송
    send(sock, hello, strlen(hello), 0);
    printf("클라이언트가 서버에게 메시지를 보냈습니다.\n");

    // 5. 데이터 수신 및 출력
    valread = read(sock, buffer, 1024);
    printf("서버로부터 받은 메시지: %s\n", buffer);

    // 6. 소켓 종료
    close(sock);

    return 0;
}
