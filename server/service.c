//
// Created by Junyeong on 2025. 9. 2..
//


#include "service.h"

#include <math.h>

#include "tui.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
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

void handle_client_request(int client_socket, char* buffer, const char* username) {
    char log_message[BUF_SIZE + 100] = {0};
    FILE *pipe;

    if (strlen(buffer) == 0) return;

    snprintf(log_message, sizeof(log_message), "[%s] Received: %s", username, buffer);
    display_server_log(log_message);

    if (strcmp(buffer, "get_fstab_quota_list") == 0) {
        snprintf(log_message, sizeof(log_message), "[%s] Executing: get_fstab_quota_list", username);
        display_server_log(log_message);

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
        return;
    }

    if (strchr(buffer, ':')) {
        char temp_buffer[BUF_SIZE];
        strcpy(temp_buffer, buffer);

        char *token;
        char *parts[5] = {NULL};
        int i = 0;
        token = strtok(temp_buffer, ":");
        while(token != NULL && i < 5) {
            parts[i++] = token;
            token = strtok(NULL, ":");
        }

        char *target_username = parts[0];
        char *method = parts[1];

        if (strcmp(method, "getinfo") == 0) {
            snprintf(log_message, sizeof(log_message), "[%s] Getting info for user: %s", username, target_username);
            display_server_log(log_message);
            struct passwd *user_info = getpwnam(target_username);
            if (user_info == NULL) {
                display_server_log("user not found");
            } else {
                snprintf(log_message, BUF_SIZE,
                 "\n---- User Info: %s ----\n"
                 "  UID   : %u\n"
                 "  GID   : %u\n"
                 "  Home : %s\n"
                 "  Shell: %s\n"
                 "----------------------",
                 user_info->pw_name, user_info->pw_uid, user_info->pw_gid, user_info->pw_dir, user_info->pw_shell);
                send(client_socket, log_message, strlen(log_message), 0);
                display_server_log("User info sent to client.");
            }
        } else if (strcmp(method, "get_proc") == 0) {
            snprintf(log_message, sizeof(log_message), "[%s] Getting process list for user: %s", username, target_username);
            display_server_log(log_message);
            char command[BUF_SIZE];
            snprintf(command, sizeof(command), "ps -u %s", target_username);
            pipe = popen(command, "r");
            char buf[BUF_SIZE];
            if (pipe == NULL) { perror("pipe open error"); }
            while (fgets(buf, BUF_SIZE, pipe) != NULL) {
                if (send(client_socket, buf, strlen(buf), 0) < 0) {
                    perror("send failed");
                    break;
                }
            }
            pclose(pipe);
            send(client_socket, "END_OF_LIST\n", 12, 0);
            display_server_log("Get process list method end");
        } else if (strcmp(method, "get_quota") == 0) {
            snprintf(log_message, sizeof(log_message), "[%s] Getting quota for user: %s", username, target_username);
            display_server_log(log_message);
            char command[BUF_SIZE];
            snprintf(command, sizeof(command), "quota -u %s 2>&1", target_username);
            pipe = popen(command, "r");
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
            snprintf(log_message, sizeof(log_message), "[%s] Setting quota for %s on %s: soft=%s, hard=%s", username, target_username, filesystem, soft_limit, hard_limit);
            display_server_log(log_message);
            char command[BUF_SIZE];
            snprintf(command, sizeof(command), "setquota -u %s %s %s 0 0 %s 2>&1", target_username, soft_limit, hard_limit, filesystem);
            pipe = popen(command, "r");
            if (pipe == NULL) {
                send(client_socket, "Failed to execute setquota. Are you root?\n", 42, 0);
            } else {
                char result_msg[BUF_SIZE];
                snprintf(result_msg, sizeof(result_msg), "Quota for %s on %s has been set.\n", target_username, filesystem);
                send(client_socket, result_msg, strlen(result_msg), 0);
                pclose(pipe);
            }
            send(client_socket, "END_OF_LIST\n", 12, 0);
            display_server_log("Set quota method end");
        }
        return;
    }

    if (strcmp(buffer, "exit") == 0) {
        snprintf(log_message, sizeof(log_message), "[%s] disconnected.", username);
        display_server_log(log_message);
        close(client_socket);
        return;
    }

    if (strcmp(buffer, "getu") == 0) {
        snprintf(log_message, sizeof(log_message), "[%s] Executing: awk -F: '{print $1}' /etc/passwd", username);
        display_server_log(log_message);
        pipe = popen("awk -F: '{print $1}' /etc/passwd", "r");
        if (pipe == NULL) {
            perror("popen failed");
            send(client_socket, "ERROR\n", 6, 0);
        } else {
            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), pipe) != NULL) {
                send(client_socket, line, strlen(line), 0);
            }
            pclose(pipe);
        }
        send(client_socket, "END_OF_LIST\n", 12, 0);
        display_server_log("Get user method end");
        return;
    }
}



