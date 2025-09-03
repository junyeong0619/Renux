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
#include <pthread.h>
#include "tui.h"

#define PORT 8080
#define BUF_SIZE 1024

typedef struct {
    int sock;
    ChatWindows wins;
} thread_args_t;

void *receive_handler(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    int sock = thread_args->sock;
    ChatWindows wins = thread_args->wins;
    char server_reply[BUF_SIZE];
    ssize_t read_size;

    while((read_size = read(sock, server_reply, BUF_SIZE - 1)) > 0) {
        server_reply[read_size] = '\0';
        display_chat_message(wins.recv_win, "server", server_reply);
    }

    if(read_size == 0) {
        display_chat_message(wins.recv_win, "system", "Disconnected from server");
    } else if(read_size == -1) {
        display_chat_message(wins.recv_win, "system", "Error reading from server");
    }

    cleanup_client_tui();
    printf("\nDisconnected from server.\n");

    return 0;
}


int main() {
    int sock = 0;
    ssize_t valread;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    ChatWindows wins;

    init_client_tui(&wins);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        display_chat_message(wins.recv_win, "Error", "socket generating dismiss");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        display_chat_message(wins.recv_win, "error", "invalid ip address.");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        display_chat_message(wins.recv_win, "error", "Connection Failed");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }
    display_chat_message(wins.recv_win, "system", "Connected to server");

    valread = read(sock, buffer, BUF_SIZE - 1);
    if (valread > 0) {
        buffer[valread] = '\0';
        display_chat_message(wins.recv_win, "server", buffer);
    }

    get_client_input(wins.send_win, buffer, BUF_SIZE);
    send(sock, buffer, strlen(buffer), 0);


    valread = read(sock, buffer, BUF_SIZE - 1);
    if (valread > 0) {
        buffer[valread] = '\0';
        display_chat_message(wins.recv_win, "server", buffer);

        if (strcmp(buffer, "logsuc") == 0) {
            display_chat_message(wins.recv_win, "system", "put 'exit' to exit");

            pthread_t recv_thread;
            thread_args_t args;
            args.sock = sock;
            args.wins = wins;

            if (pthread_create(&recv_thread, NULL, receive_handler, (void*)&args) < 0) {
                perror("Receive thread generating failed.");
                cleanup_client_tui();
                exit(EXIT_FAILURE);
            }

            while(1) {
                get_client_input(wins.send_win, buffer, BUF_SIZE);
                send(sock, buffer, strlen(buffer), 0);

                if (strcmp(buffer, "exit") == 0) {
                    break;
                }
            }
        } else {
            display_chat_message(wins.recv_win, "system", "Login failed");
            sleep(2);
        }
    }

    close(sock);
    cleanup_client_tui();

    return 0;
}