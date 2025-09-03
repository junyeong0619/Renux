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

void generate_socket(int *server_fd) {
    if ((*server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        display_server_log("Error: Socket generating failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
}

void get_server_password(char *server_passwd) {
    display_server_log("Set the password for Client accepting.");
    get_server_input(server_passwd, BUF_SIZE);
    display_server_log("Password save completed.");
}

void server_cleanup(int new_socket, int server_fd, char *username) {
    close(new_socket);
    close(server_fd);

    display_server_log("Exiting Server...");
    sleep(2);
    cleanup_server_tui();

    //free dynamic variables
    free(username);
}
int main() {
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    char *username;

    //기본정보 초기화
    username = get_username();

    init_server_tui();

    generate_socket(&server_fd);


    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        display_server_log("Error: Binding failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        display_server_log("Error: Listening failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }

    display_server_log(strcat(username,"now opened server."));

    char server_passwd[BUF_SIZE];
    get_server_password(server_passwd);


    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        display_server_log("Error: Accepting failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }

    display_server_log("Connection established.");

    const char *login_msg = "Put the login information in this form: username,password";
    send(new_socket, login_msg, strlen(login_msg), 0);

    valread = read(new_socket, buffer, BUF_SIZE - 1);

    if (valread > 0) {
        buffer[valread] = '\0';

        char data[BUF_SIZE];
        strcpy(data, buffer);

        char *get_username = strtok(data, ",");

        char *password = strtok(NULL, ",\n");

        if (username != NULL && password != NULL) {

            if (is_valid_login(get_username, password,server_passwd) == 0) {
                const char *success_msg = "logsuc";
                send(new_socket, success_msg, strlen(success_msg), 0);
                display_server_log("login succeeded. Waiting for command.");

                start_chat_service(new_socket);

            } else {
                const char *failure_msg = "Login failed";
                send(new_socket, failure_msg, strlen(failure_msg), 0);
                display_server_log("Could not login.");
            }

        } else {
            const char *failure_msg = "Login failed. incorrect form error";
            send(new_socket, failure_msg, strlen(failure_msg), 0);
            display_server_log("login Failed");
        }
    }

    server_cleanup(new_socket, server_fd, username);

    return 0;
}
