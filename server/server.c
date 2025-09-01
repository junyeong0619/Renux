//
// Created by Junyeong on 2025. 9. 2..
//
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080

int main() {
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    const char *hello = "Hello from server";

    // 1. 소켓 생성
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 2. 소켓에 주소 바인딩
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 3. 연결 요청 대기
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("서버가 8080 포트에서 대기 중...\n");

    // 4. 클라이언트 연결 수락
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    printf("클라이언트가 연결되었습니다.\n");

    // 5. 데이터 수신 및 출력
    valread = read(new_socket, buffer, 1024);
    printf("클라이언트로부터 받은 메시지: %s\n", buffer);

    // 6. 데이터 전송
    send(new_socket, hello, strlen(hello), 0);
    printf("서버가 클라이언트에게 메시지를 보냈습니다.\n");

    // 7. 소켓 종료
    close(new_socket);
    close(server_fd);

    return 0;
}
