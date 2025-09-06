//
// Created by Junyeong on 2025. 9. 2..
//

#include "service.h"
#include "tui.h"
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <pwd.h>

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

void send_etc_passwd(int client_socket) {
    struct passwd *user_info;
    char buffer[BUF_SIZE];
    int len;

    setpwent();

    while ((user_info = getpwent()) != NULL) {
        len = snprintf(buffer, BUF_SIZE, "name: %s, passwd: %s, home dir: %s, shell: %s,\n",
                       user_info->pw_name,
                       user_info->pw_passwd,
                       user_info->pw_dir,
                       user_info->pw_shell
                       );

        if (len < 0 || len >= BUF_SIZE) {
            fprintf(stderr, "buffer overflow\n");
            continue;
        }

        if (send(client_socket, buffer, len, 0) < 0) {
            perror("send failed");
            break;
        }
    }

    endpwent();
}

void start_chat_service(int client_socket) {
    char buffer[BUF_SIZE] = {0};
    char send_buffer[BUF_SIZE] = {0};
    ssize_t valread;

    while(1) {
        valread = read(client_socket, buffer, BUF_SIZE - 1);
        if (valread <= 0) {
            display_server_log("client disconnected.");
            break;
        }
        buffer[valread] = '\0';

        if (strcmp(buffer, "exit") == 0) {
            display_server_log("client disconnected.");
            break;
        }

        if (strcmp(buffer, "passinfo") == 0) {
            FILE *pipe = popen("ls","r");
            char buf[BUF_SIZE];
            if (pipe == NULL) {
                perror("pipe open error");
            }

            while (fgets(buf, BUF_SIZE, pipe) != NULL) {
                if (send(client_socket, buf, strlen(buf), 0) < 0) {
                    perror("send failed");
                    break;
                }
            }
            pclose(pipe);
        }

        if (strcmp(buffer, "getpw") == 0) {
            send_etc_passwd(client_socket);
        }

        if (strcmp(buffer, "get_users") == 0) {
            FILE *pipe;
            char line[BUF_SIZE];

            pipe = popen("awk -F: '{print $1}' /etc/passwd", "r");
            if (pipe == NULL) {
                perror("popen failed");
                send(client_socket, "ERROR\n", 6, 0);
            } else {
                while (fgets(line, sizeof(line), pipe) != NULL) {
                    send(client_socket, line, strlen(line), 0);
                }
                pclose(pipe);
            }
            send(client_socket, "END_OF_LIST\n", 12, 0);
        }

        char log_message[BUF_SIZE + 50];
        snprintf(log_message, sizeof(log_message), "message from client: %s", buffer);
        display_server_log(log_message);
    }
}
