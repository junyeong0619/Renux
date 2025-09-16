//
// Created by Junyeong on 2025. 9. 2..
//

#include "service.h"

#include <math.h>

#include "tui.h"
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <pwd.h>
#include "../utils/ssl_utils.h"


#define BUF_SIZE 1024

static void safe_log_message_concat(char *message, char *string,   char *buffer) {
    snprintf(buffer, BUF_SIZE , string, message);
    display_server_log(buffer);
}

char *get_username(void) {
    char *username = getlogin();
    char *return_username = malloc(strlen(username) + 1);
    strcpy(return_username, username);
    return return_username;
}

int is_valid_login(char *username, char *passwd, unsigned long server_passwd_hashed) {
    if (username == NULL || passwd == NULL)
        return -1;

    char *target_username = get_username();
    int is_user_valid = (strcmp(username, target_username) == 0);
    free(target_username);

    if (is_user_valid) {
        unsigned long incoming_passwd_hashed = hash_string(passwd);
        if (server_passwd_hashed == incoming_passwd_hashed) {
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

void start_server_service(int client_socket) {
    char buffer[BUF_SIZE] = {0};
    char send_buffer[BUF_SIZE] = {0};
    char log_message[BUF_SIZE+100] = {0};
    ssize_t valread;

    while(1) {
        valread = read(client_socket, buffer, BUF_SIZE - 1);
        if (valread <= 0) {
            display_server_log("client disconnected.");
            break;
        }
        buffer[valread] = '\0';

        if(strcmp(buffer, "get_fstab_quota_list") == 0) {
            display_server_log("server get_fstab_quota_list method started");
            FILE *fp = fopen("/etc/fstab", "r");
            if (fp == NULL) {
                send(client_socket, "ERROR: Cannot open /etc/fstab\n", 31, 0);
            } else {
                char line[BUF_SIZE];
                while (fgets(line, sizeof(line), fp)) {
                    if (line[0] == '#' || line[0] == '\n') continue;

                    if (strstr(line, "usrquota") != NULL) {
                        char fs_spec[100], fs_file[100];
                        sscanf(line, "%s %s", fs_spec, fs_file);

                        char mount_path[128];
                        snprintf(mount_path, sizeof(mount_path), "%s\n", fs_file);
                        send(client_socket, mount_path, strlen(mount_path), 0);
                    }
                }
                fclose(fp);
            }
            send(client_socket, "END_OF_LIST\n", 12, 0);
            display_server_log("Get fstab quota list method end");
            continue;
        }

        if(strchr(buffer,':')) {
            display_server_log(buffer);
            display_server_log("server getinfo method started");

            char *token;
            char *parts[5] = {NULL}; // username, method, arg1, arg2, arg3
            int i = 0;
            token = strtok(buffer, ":");
            while(token != NULL && i < 5) {
                parts[i++] = token;
                token = strtok(NULL, ":");
            }

            char *username = parts[0];
            char *method = parts[1];

            if (strcmp(method,"getinfo")==0) {
                struct passwd *user_info = getpwnam(username);
                if (user_info == NULL) {
                    display_server_log("user not found");
                }else {
                    snprintf(log_message, BUF_SIZE,
                     "\n---- User Info: %s ----\n"
                     "  UID   : %u\n"
                     "  GID   : %u\n"
                     "  Home : %s\n"
                     "  Shell: %s\n"
                     "----------------------",
                     user_info->pw_name,
                     user_info->pw_uid,
                     user_info->pw_gid,
                     user_info->pw_dir,
                     user_info->pw_shell);

                    send(client_socket, log_message, strlen(log_message), 0);
                    display_server_log("User info sent to client.");
                }
            }else if (strcmp(method, "get_proc") == 0) {
                display_server_log("server get_proc method started");
                char command[BUF_SIZE];
                snprintf(command, sizeof(command), "ps -u %s", username);
                FILE *pipe = popen(command, "r");
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
                send(client_socket, "END_OF_LIST\n", 12, 0);
                display_server_log("Get process list method end");
            }else if (strcmp(method, "get_quota") == 0) {
                display_server_log("server get_quota method started");
                char command[BUF_SIZE];
                snprintf(command, sizeof(command), "quota -u %s 2>&1", username);
                FILE *pipe = popen(command, "r");
                char buf[BUF_SIZE];
                while (fgets(buf, BUF_SIZE, pipe) != NULL) {
                    send(client_socket, buf, strlen(buf), 0);
                }
                pclose(pipe);
                send(client_socket, "END_OF_LIST\n", 12, 0);
                display_server_log("Get quota method end");

            } else if (strcmp(method, "set_quota") == 0) {
                char *soft_limit = parts[2];
                char *hard_limit = parts[3];
                char *filesystem = parts[4];


                display_server_log("server set_quota method started");
                char command[BUF_SIZE];
                snprintf(command, sizeof(command), "setquota -u %s %s %s 0 0 %s", username, soft_limit, hard_limit, filesystem);

                FILE *pipe = popen(command, "r");
                if (pipe == NULL) {
                    send(client_socket, "Failed to execute setquota. Are you root?\n", 42, 0);
                } else {
                    char result_msg[BUF_SIZE];
                    snprintf(result_msg, sizeof(result_msg), "Quota for %s on %s has been set.\n", username, filesystem);
                    send(client_socket, result_msg, strlen(result_msg), 0);
                    pclose(pipe);
                }
                send(client_socket, "END_OF_LIST\n", 12, 0);
                display_server_log("Set quota method end");
            }

        }

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

        //todo 실시간 작업 현황 보고필요
        if (strcmp(buffer, "getu") == 0) {
            FILE *pipe;
            char line[BUF_SIZE];

            //todo 데이터전송시 암호화 필요
            display_server_log("Server started command getu");
            pipe = popen("awk -F: '{print $1}' /etc/passwd", "r");
            display_server_log("pipe opened with \" awk -F: '{print $1}' /etc/passwd \"");
            if (pipe == NULL) {
                perror("popen failed");
                send(client_socket, "ERROR\n", 6, 0);
            } else {
                while (fgets(line, sizeof(line), pipe) != NULL) {
                    safe_log_message_concat("server:", line, log_message);
                    send(client_socket, line, strlen(line), 0);
                }
                pclose(pipe);
            }
            send(client_socket, "END_OF_LIST\n", 12, 0);
            display_server_log("Get user method end");
        }
        safe_log_message_concat(buffer, "message from client: %s",log_message);
    }
}
