//
// Created by Junyeong on 2025. 9. 2..
//
#include "server.h"

#include <pwd.h>
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
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static void generate_socket(int *server_fd) {
    if ((*server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        display_server_log("Error: Socket generating failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
}

static void get_server_password(char *server_passwd) {
    display_server_log("Set the password for Client accepting.");
    get_server_input(server_passwd, BUF_SIZE);
    display_server_log("Password save completed.");
}

static void server_cleanup(int new_socket, int server_fd, char *username) {
    close(new_socket);
    close(server_fd);

    display_server_log("Exiting Server...");
    sleep(2);
    cleanup_server_tui();

    //free dynamic variables
    free(username);
}

static void login_process(char *get_user_name, char *password, char *server_passwd, int new_socket) {
    if (is_valid_login(get_user_name, password,server_passwd) == 0) {
        const char *success_msg = "logsuc";
        send(new_socket, success_msg, strlen(success_msg), 0);
        display_server_log("login succeeded. Waiting for command.");

        start_server_service(new_socket);

    } else {
        const char *failure_msg = "Login failed";
        send(new_socket, failure_msg, strlen(failure_msg), 0);
        display_server_log("Could not login.");
    }
}

static void safe_log_message_concat(char *message, char *string,   char *buffer) {
    snprintf(buffer, sizeof(buffer), string, message);
    display_server_log(buffer);
}

int main() {
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    char log_message[BUF_SIZE + 100];
    char *username;

    //기본정보 초기화
    username = get_username();

    init_server_tui();

    generate_socket(&server_fd);
    display_server_log("Server socket generated");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (likely(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)) {
        display_server_log("Error: Binding failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("Server binding succeeded");

    if (likely(listen(server_fd, 3) < 0)) {
        display_server_log("Error: Listening failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("Server Listening succeeded Waiting for client connection...");

    safe_log_message_concat(username, "\tnow opened server.",log_message);

    char server_passwd[BUF_SIZE];
    get_server_password(server_passwd);


    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        display_server_log("Error: Accepting failed");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("Server accepting client...");

    display_server_log("Connection established.");

    const char *login_msg = "Put the login information in this form: username,password";
    send(new_socket, login_msg, strlen(login_msg), 0);

    display_server_log("Server waiting for client's input...");
    valread = read(new_socket, buffer, BUF_SIZE - 1);
    if (likely(valread > 0)) {
        buffer[valread] = '\0';

        char data[BUF_SIZE];
        strcpy(data, buffer);

        safe_log_message_concat(data, "Server received a response from client.\nclient's original response:\t%s", log_message);

        char *get_user_name = strtok(data, ",");
        char *password = strtok(NULL, ",\n");
        safe_log_message_concat(get_user_name,"Server get username from response:\t",log_message);
        safe_log_message_concat(password,"Server get password from response:\t",log_message);

        if (username != NULL && password != NULL) {
            login_process(get_user_name, password, server_passwd, new_socket);
            display_server_log("Server login succeeded.");
        } else {
            const char *failure_msg = "Login failed. incorrect form error";
            send(new_socket, failure_msg, strlen(failure_msg), 0);
            display_server_log("login Failed");
        }
    }

    server_cleanup(new_socket, server_fd, username);

    return 0;
}
