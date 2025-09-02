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
#include "service.h"

#define PORT 8080
#define BUF_SIZE 1024


int main() {
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    char *username;

    //기본정보 초기화
    username = get_username();

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

    display_server_log(strcat(username,"가 서버를 열었습니다!!"));
    display_server_log("클라이언트가 요청할때 설정할 비밀번호를 입력해주세요.");

    char server_passwd[BUF_SIZE];
    get_server_input(server_passwd, BUF_SIZE);
    display_server_log("비밀번호 저장완료");


    // 5. 클라이언트 연결 수락
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        display_server_log("오류: 연결 수락 실패");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("클라이언트가 연결되었습니다.");

    const char *login_msg = "로그인 정보를 입력하세요: 사용자이름,비밀번호";
    send(new_socket, login_msg, strlen(login_msg), 0);

    valread = read(new_socket, buffer, BUF_SIZE - 1);

    if (valread > 0) {
        buffer[valread] = '\0';

        // strtok은 원본을 훼손하므로, 복사본을 만들어 사용합니다.
        char data[BUF_SIZE];
        strcpy(data, buffer);

        // 1. 사용자 이름 분리 (쉼표 기준)
        char *get_username = strtok(data, ",");

        // 2. 비밀번호 분리 (쉼표 또는 개행 문자 기준)
        //    -> 비밀번호 끝에 붙어있을 개행 문자를 한번에 처리하는 팁입니다.
        char *password = strtok(NULL, ",\n");
        printf("username %s\n", username);
        printf("password %s\n", password);

        // 3. ID와 PW가 모두 정상적으로 분리되었는지 확인
        if (username != NULL && password != NULL) {

            if (is_valid_login(get_username, password,server_passwd) == 0) {
                // --- 로그인 성공 처리 ---
                const char *success_msg = "로그인 성공!";
                send(new_socket, success_msg, strlen(success_msg), 0);
                display_server_log("로그인 성공: 채팅을 시작합니다.");

                // --- 채팅 루프 시작 ---
                while(1) {
                    // 기존 채팅 로직 ...
                    valread = read(new_socket, buffer, BUF_SIZE - 1);
                    if (valread <= 0) { // 클라이언트 연결 끊김 확인
                        display_server_log("클라이언트 연결이 끊어졌습니다.");
                        break;
                    }
                    buffer[valread] = '\0';

                    if (strcmp(buffer, "exit") == 0) {
                        display_server_log("클라이언트가 채팅을 종료했습니다.");
                        break;
                    }

                    char log_message[BUF_SIZE + 30];
                    snprintf(log_message, sizeof(log_message), "클라이언트로부터 받은 메시지: %s", buffer);
                    display_server_log(log_message);

                    // 서버 입력 및 전송
                    char send_buffer[BUF_SIZE] = {0};
                    get_server_input(send_buffer, BUF_SIZE);
                    if (strlen(send_buffer) > 0) {
                        send(new_socket, send_buffer, strlen(send_buffer), 0);
                        display_server_log("서버가 클라이언트에게 메시지를 보냈습니다.");
                    }
                }

            } else {
                // --- 로그인 실패 처리 (ID/PW 불일치) ---
                const char *failure_msg = "로그인 실패. 연결을 종료합니다.";
                send(new_socket, failure_msg, strlen(failure_msg), 0);
                display_server_log("클라이언트 로그인 실패: ID 또는 PW 불일치.");
            }

        } else {
            // --- 로그인 실패 처리 (잘못된 형식) ---
            const char *failure_msg = "로그인 실패: 잘못된 형식입니다. (ID,PW)";
            send(new_socket, failure_msg, strlen(failure_msg), 0);
            display_server_log("클라이언트 로그인 실패: 잘못된 형식 수신.");
        }
    }


    // 8. 소켓 종료 및 TUI 정리
    close(new_socket); // 채팅 루프가 끝나거나 로그인 실패 시 소켓을 닫음
    close(server_fd);

    display_server_log("서버를 종료합니다...");
    sleep(2); // 메시지를 볼 시간을 줌
    cleanup_server_tui();

    //free dynamic variables
    free(username);

    return 0;
}
