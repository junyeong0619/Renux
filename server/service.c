//
// Created by Junyeong on 2025. 9. 2..
//

#include "service.h"
#include "tui.h"
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#define BUF_SIZE 1024

char *get_username(void) {
    char *username = getlogin();
    char *return_username = malloc(strlen(username) + 1);
    strcpy(return_username, username);
    return return_username;
}

int is_valid_login(char *username,char *passwd, char *server_passwd) {
    if (username == NULL)
        return -1;
    char *target_username = get_username();
    if (strcmp(username, target_username) == 0) {
        free(target_username);
        if (strcmp(server_passwd,passwd) == 0) {
            return 0;
        }
    }
    return -1;
}

void start_chat_service(int client_socket) {
    char buffer[BUF_SIZE] = {0};
    char send_buffer[BUF_SIZE] = {0};
    ssize_t valread;

    while(1) {
        valread = read(client_socket, buffer, BUF_SIZE - 1);
        if (valread <= 0) {
            display_server_log("클라이언트 연결이 끊어졌습니다.");
            break;
        }
        buffer[valread] = '\0';

        if (strcmp(buffer, "exit") == 0) {
            display_server_log("클라이언트가 채팅을 종료했습니다.");
            break;
        }

        char log_message[BUF_SIZE + 50];
        snprintf(log_message, sizeof(log_message), "클라이언트로부터 받은 메시지: %s", buffer);
        display_server_log(log_message);

        get_server_input(send_buffer, BUF_SIZE);
        if (strlen(send_buffer) > 0) {
            send(client_socket, send_buffer, strlen(send_buffer), 0);
            display_server_log("서버가 클라이언트에게 메시지를 보냈습니다.");
        }
    }
}
