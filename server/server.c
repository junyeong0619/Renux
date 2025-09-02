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
#include "tui.h"

#define PORT 8080
#define BUF_SIZE 1024

int main() {
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};

    // 1. TUI 초기화
    init_server_tui();

    // 2. 소켓 생성
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        display_server_log("오류: 소켓 생성 실패");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 3. 소켓에 주소 바인딩
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        display_server_log("오류: 바인드 실패");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }

    // 4. 연결 요청 대기
    if (listen(server_fd, 3) < 0) {
        display_server_log("오류: 리슨 실패");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("서버가 8080 포트에서 대기 중...");

    // 5. 클라이언트 연결 수락
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        display_server_log("오류: 연결 수락 실패");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("클라이언트가 연결되었습니다.");

    // 6. 데이터 수신 및 출력
    valread = read(new_socket, buffer, BUF_SIZE);
    if (valread > 0) {
        buffer[valread] = '\0';
        char log_message[BUF_SIZE + 30];
        snprintf(log_message, sizeof(log_message), "클라이언트로부터 받은 메시지: %s", buffer);
        display_server_log(log_message);
    }

    // 7. 데이터 전송 (TUI 입력 사용)
    char send_buffer[BUF_SIZE] = {0};
    get_server_input(send_buffer, BUF_SIZE);
    send(new_socket, send_buffer, strlen(send_buffer), 0);
    display_server_log("서버가 클라이언트에게 메시지를 보냈습니다.");

    // 8. 소켓 종료 및 TUI 정리
    close(new_socket);
    close(server_fd);

    display_server_log("서버를 종료합니다...");
    sleep(2); // 메시지를 볼 시간을 줌
    cleanup_server_tui();

    return 0;
}
