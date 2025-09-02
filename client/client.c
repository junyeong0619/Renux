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
#include "tui.h"

#define PORT 8080
#define BUF_SIZE 1024

int main() {
    int sock = 0;
    ssize_t valread;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    ChatWindows wins;

    // 1. TUI 초기화
    init_client_tui(&wins);

    // 2. 소켓 생성
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        display_chat_message(wins.recv_win, "오류", "소켓 생성 실패");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        display_chat_message(wins.recv_win, "오류", "유효하지 않은 주소입니다.");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }

    // 3. 서버에 연결
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        display_chat_message(wins.recv_win, "오류", "연결 실패");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }
    display_chat_message(wins.recv_win, "시스템", "서버에 연결되었습니다.");

    // 서버로부터 로그인 요청 메시지 받기
    valread = read(sock, buffer, BUF_SIZE - 1);
    if (valread > 0) {
        buffer[valread] = '\0';
        display_chat_message(wins.recv_win, "서버", buffer);
    }

    // 사용자로부터 로그인 정보 입력받고 서버로 전송
    get_client_input(wins.send_win, buffer, BUF_SIZE);
    send(sock, buffer, strlen(buffer), 0);

    // 서버로부터 로그인 결과 메시지 받기
    valread = read(sock, buffer, BUF_SIZE - 1);
    if (valread > 0) {
        buffer[valread] = '\0';
        display_chat_message(wins.recv_win, "서버", buffer);

        // [수정됨] 서버가 보내는 "로그인 성공!" 메시지와 정확히 비교
        if (strcmp(buffer, "로그인 성공!") == 0) {
            // 로그인 성공 시에만 채팅 루프 시작 (goto 제거)
            display_chat_message(wins.recv_win, "시스템", "채팅을 시작합니다. 'exit'를 입력해 종료하세요.");

            // 4. 데이터 전송 및 수신 루프
            while(1) {
                // 사용자 입력 받기
                get_client_input(wins.send_win, buffer, BUF_SIZE);

                if (strcmp(buffer, "exit") == 0) {
                    send(sock, buffer, strlen(buffer), 0);
                    break; // 루프 탈출
                }

                // 서버로 데이터 전송
                send(sock, buffer, strlen(buffer), 0);

                // 서버로부터 응답 받기
                valread = read(sock, buffer, BUF_SIZE - 1);
                if (valread > 0) {
                    buffer[valread] = '\0';
                    display_chat_message(wins.recv_win, "서버", buffer);
                } else {
                    display_chat_message(wins.recv_win, "시스템", "서버와의 연결이 끊겼습니다.");
                    break; // 루프 탈출
                }
            }
        } else {
            // 로그인 실패 시
            display_chat_message(wins.recv_win, "시스템", "로그인에 실패했습니다. 프로그램을 종료합니다.");
            sleep(2); // 메시지를 볼 시간을 줌
        }
    }

    // 5. 소켓 종료 및 TUI 정리
    close(sock);
    cleanup_client_tui();

    return 0;
}
