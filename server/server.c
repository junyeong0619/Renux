//
// Created by Junyeong on 2025. 9. 2..
//
#include "server.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tui.h"
#include "service.h"
#include "../utils/ssl_utils.h"
#include "../utils/log.h"
#ifdef __APPLE__
    #include <sys/event.h>
#elif __linux__
    #include <sys/epoll.h>
#endif


#define PORT 8080
#define BUF_SIZE 1024
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MAX_EVENTS 128
#define USERNAME_MAX_LEN 32


typedef struct {
    int fd;
    int is_logged_in;
    char username[USERNAME_MAX_LEN];
    char ip_addr[INET_ADDRSTRLEN];
    time_t last_activity;
} client_state;

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
    cleanup_logger();\
    cleanup_server_tui();

    //free dynamic variables
    free(username);
}

static void safe_log_message_concat(char *message, char *string,   char *buffer) {
    snprintf(buffer, BUF_SIZE, string, message);
    display_server_log(buffer);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char log_message[BUF_SIZE + 100];
    char *username;

    //기본정보 초기화
    username = get_username();

    init_server_tui();

    init_server_tui();
    init_logger("server.log");


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

    //hashing server password
    char server_passwd_plain[BUF_SIZE];
    get_server_password(server_passwd_plain);

    unsigned long server_passwd_hashed = hash_string(server_passwd_plain);

    memset(server_passwd_plain, 0, sizeof(server_passwd_plain));

    char hashed_msg[100];
    snprintf(hashed_msg, sizeof(hashed_msg), "Password has been hashed. Hash: %lu", server_passwd_hashed);
    display_server_log(hashed_msg);

#ifdef __APPLE__
    int kq = kqueue();
    if (kq == -1) {
        perror("kqueue");
        exit(EXIT_FAILURE);
    }

    struct kevent change_event;
    struct kevent event_list[MAX_EVENTS];
#elif __linux__
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event, events[MAX_EVENTS];
#endif

    client_state clients[MAX_EVENTS];
    for (int i = 0; i < MAX_EVENTS; i++) {
        clients[i].fd = -1;
        clients[i].is_logged_in = 0;
    }

#ifdef __APPLE__
    EV_SET(&change_event, server_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (kevent(kq, &change_event, 1, NULL, 0, NULL) == -1) {
        perror("kevent register");
        exit(EXIT_FAILURE);
    }
#elif __linux__
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
#endif

    display_server_log("Server is running with event loop...");

    while (1) {
#ifdef __APPLE__
        int num_events = kevent(kq, NULL, 0, event_list, MAX_EVENTS, NULL);
#elif __linux__
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
#endif

        if (num_events == -1) {
#ifdef __APPLE__
            perror("kevent wait");
#elif __linux__
            perror("epoll_wait");
#endif
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < num_events; i++) {
#ifdef __APPLE__
            int event_fd = event_list[i].ident;
#elif __linux__
            int event_fd = events[i].data.fd;
#endif

#ifdef __APPLE__
            if (event_list[i].flags & EV_EOF) {
#elif __linux__
            if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
#endif
                display_server_log("Client disconnected.");
                close(event_fd);
                for (int j = 0; j < MAX_EVENTS; j++) {
                    if (clients[j].fd == event_fd) {
                        clients[j].fd = -1;
                        clients[j].is_logged_in = 0;
                        break;
                    }
                }
            } else if (event_fd == server_fd) {
                int client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
                if (client_socket == -1) {
                    perror("accept");
                    continue;
                }

#ifdef __APPLE__
                EV_SET(&change_event, client_socket, EVFILT_READ, EV_ADD, 0, 0, 0);
                kevent(kq, &change_event, 1, NULL, 0, NULL);
#elif __linux__
                event.events = EPOLLIN | EPOLLET;
                event.data.fd = client_socket;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &event) == -1) {
                    perror("epoll_ctl");
                    exit(EXIT_FAILURE);
                }
#endif

                for (int j = 0; j < MAX_EVENTS; j++) {
                    if (clients[j].fd == -1) {
                        clients[j].fd = client_socket;
                        if (address.sin_family == AF_INET) {
                            inet_ntop(AF_INET, &address.sin_addr, clients[j].ip_addr, INET_ADDRSTRLEN);
                        }
                        break;
                    }
                }

                display_server_log("New client connected.");
                const char *login_msg = "Put the login information in this form: username,password";
                send(client_socket, login_msg, strlen(login_msg), 0);

            } else {
                char buffer[BUF_SIZE] = {0};
                ssize_t valread = read(event_fd, buffer, BUF_SIZE - 1);

                if (valread > 0) {
                    buffer[valread] = '\0';
                    buffer[strcspn(buffer, "\n")] = 0;

                    client_state* current_client = NULL;
                    for (int j = 0; j < MAX_EVENTS; j++) {
                        if (clients[j].fd == event_fd) {
                            current_client = &clients[j];
                            break;
                        }
                    }

                    if (current_client == NULL) continue; // safety check

                    if (current_client->is_logged_in) {
                        handle_client_request(event_fd, buffer, current_client->username);
                    } else {
                        char data[BUF_SIZE];
                        strcpy(data, buffer);
                        char *get_user_name = strtok(data, ",");
                        char *password = strtok(NULL, ",");

                        if (get_user_name && password && is_valid_login(get_user_name, password, server_passwd_hashed) == 0) {
                            current_client->is_logged_in = 1;
                            strncpy(current_client->username, get_user_name, USERNAME_MAX_LEN - 1);
                            send(event_fd, "logsuc", 6, 0);
                            display_server_log("Client login successful.");
                            char log_buf[256];
                            snprintf(log_buf, sizeof(log_buf), "Client login successful: %s@%s", current_client->username, current_client->ip_addr);
                            display_server_log(log_buf);
                        } else {
                            send(event_fd, "Login failed", 12, 0);
                            display_server_log("Client login failed.");
                        }
                    }
                }
            }
        }
    }

    server_cleanup(new_socket, server_fd, username);

    return 0;
}