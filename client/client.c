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
#include <stdbool.h>
#include "tui.h"
#include "../server/service.h"

#define BUF_SIZE 1024
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

volatile bool is_menu_mode = false;
char **menu_user_list = NULL;
int menu_user_count = 0;
pthread_mutex_t menu_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int sock;
    ChatWindows wins;
} thread_args_t;


static void *receive_handler(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    int sock = thread_args->sock;
    ChatWindows wins = thread_args->wins;

    char recv_buffer[BUF_SIZE];
    char line_buffer[BUF_SIZE] = {0};
    int line_len = 0;
    ssize_t read_size;

    while ((read_size = read(sock, recv_buffer, BUF_SIZE - 1)) > 0) {
        if (line_len + read_size >= BUF_SIZE) {

            line_len = 0;
            continue;
        }
        memcpy(line_buffer + line_len, recv_buffer, read_size);
        line_len += read_size;
        line_buffer[line_len] = '\0';

        char *newline_ptr;
        while ((newline_ptr = strchr(line_buffer, '\n')) != NULL) {
            *newline_ptr = '\0';
            char completed_line[BUF_SIZE];
            strcpy(completed_line, line_buffer);

            line_len = strlen(newline_ptr + 1);
            memmove(line_buffer, newline_ptr + 1, line_len + 1);

            pthread_mutex_lock(&menu_lock);
            if (is_menu_mode) {
                if (strcmp(completed_line, "END_OF_LIST") == 0) {
                    is_menu_mode = false;
                } else {
                    menu_user_count++;
                    menu_user_list = realloc(menu_user_list, sizeof(char*) * menu_user_count);
                    menu_user_list[menu_user_count - 1] = strdup(completed_line);
                }
            } else {
                display_chat_message(wins.recv_win, "server", completed_line);
            }
            pthread_mutex_unlock(&menu_lock);
        }
    }

    display_chat_message(wins.recv_win, "system", "Disconnected from server");
    cleanup_client_tui();
    printf("\nDisconnected. Press Enter to exit.\n");

    return 0;
}

static void get_users_handler(ChatWindows *wins, int sock) {
    display_chat_message(wins->recv_win, "System", "Requesting user list from server...");

    pthread_mutex_lock(&menu_lock);
    if (menu_user_list != NULL) {
        for (int i = 0; i < menu_user_count; i++) free(menu_user_list[i]);
        free(menu_user_list);
    }

    is_menu_mode = true;
    menu_user_list = NULL;
    menu_user_count = 0;
    pthread_mutex_unlock(&menu_lock);

    send(sock, "getu", strlen("getu"), 0);


    display_chat_message(wins->recv_win, "System", "User list updated.");
}

static int manage_user_functions() {
    return user_manage_function_selections();
};

static void manage_users_handler(ChatWindows *wins, int sock) {
    int selection = 0;
    pthread_mutex_lock(&menu_lock);
    if (menu_user_list != NULL && menu_user_count > 0) {


        is_menu_mode = false;
        pthread_mutex_unlock(&menu_lock);

        int choice = show_user_menu(menu_user_list, menu_user_count);
        char *selected_user = menu_user_list[choice - 1];

        selection = manage_user_functions();
        switch(selection) {
            case 0:
            {
                display_chat_message(wins->recv_win, "System", "switch 1 on");
                char command_buf[BUF_SIZE];

                snprintf(command_buf, sizeof(command_buf), "%s:getinfo", selected_user);
                display_chat_message(wins->recv_win, "System", command_buf);

                send(sock, command_buf, strlen(command_buf), 0);
                break;
            }
            default: break;
        }

        char msg[100];
        snprintf(msg, sizeof(msg), "Selected: %s number: %d", selected_user, selection+1);

        display_chat_message(wins->recv_win, "System", msg);

    } else {
        pthread_mutex_unlock(&menu_lock);
        display_chat_message(wins->recv_win, "System", "User list is empty. Please run 'get_users' first.");
    }
}


int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    ChatWindows wins;
    char *ipaddr, *port;

    if (argc == 3) {
        ipaddr = argv[1];
        port = argv[2];
    } else {
        printf("Input format in ./client <ipaddress> <port> \n");
    }

    init_client_tui(&wins);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { /* ... */ }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(port));
    if (inet_pton(AF_INET, ipaddr, &serv_addr.sin_addr) <= 0) { /* ... */ }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { /* ... */ }

    display_chat_message(wins.recv_win, "system", "Connected to server. Waiting for server message...");

    pthread_t recv_thread;
    thread_args_t args;
    args.sock = sock;
    args.wins = wins;

    //receiving thread creating
    if (likely(pthread_create(&recv_thread, NULL, receive_handler, (void*)&args) < 0)) {
        perror("Thread creation failed");
        cleanup_client_tui();
        exit(EXIT_FAILURE);
    }

    while(1) {
        get_client_input(wins.send_win, buffer, BUF_SIZE);

        if (strcmp(buffer, "getu") == 0) {
            get_users_handler(&wins, sock);
            continue;
        }

        if (strcmp(buffer, "manage") == 0) {
           manage_users_handler(&wins,sock);
            continue;
        } else{
            send(sock, buffer, strlen(buffer), 0);
        }

        if (strcmp(buffer, "exit") == 0) {
            break;
        }
    }

    //socket close and program exiting
    close(sock);
    cleanup_client_tui();
    return 0;
}