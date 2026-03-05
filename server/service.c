#include "service.h"
#include "tui.h"
#include "../utils/ssl_utils.h"
#include "../utils/exec_utils.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <pwd.h>

#define BUF_SIZE 1024

/* ------------------------------------------------------------------ */
/*  입력값 검증 (화이트리스트 기반)                                     */
/* ------------------------------------------------------------------ */

static int is_valid_username(const char *input) {
    if (input == NULL || *input == '\0') return 0;
    size_t len = strlen(input);
    if (len > 32) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-' && c != '.') return 0;
    }
    return 1;
}

/* 숫자 + 선택적 단위 접미사(K/M/G/T) */
static int is_valid_quota_value(const char *input) {
    if (input == NULL || *input == '\0') return 0;
    size_t len = strlen(input);
    if (len > 20) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (isdigit((unsigned char)c)) continue;
        if (i == len - 1 && (c=='K'||c=='M'||c=='G'||c=='T'||
                              c=='k'||c=='m'||c=='g'||c=='t')) continue;
        return 0;
    }
    return 1;
}

/* '/'로 시작하는 안전한 경로 */
static int is_valid_filesystem(const char *input) {
    if (input == NULL || input[0] != '/') return 0;
    size_t len = strlen(input);
    if (len > 128) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (!isalnum((unsigned char)c) && c != '/' && c != '_' && c != '-' && c != '.') return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  TLS 전송 헬퍼                                                       */
/* ------------------------------------------------------------------ */

/* SSL_write 래퍼: 문자열 리터럴 전송 편의 함수 */
static void ssl_send_str(SSL *ssl, const char *msg) {
    SSL_write(ssl, msg, (int)strlen(msg));
}

/*
 * exec_command_buf 결과를 SSL 소켓으로 전송 후 버퍼 해제
 * 실행 실패 시 에러 메시지 전송
 */
static void exec_and_send(SSL *ssl, const char *path, char *const argv[]) {
    size_t out_len = 0;
    char *out = exec_command_buf(path, argv, &out_len);
    if (out) {
        if (out_len > 0) SSL_write(ssl, out, (int)out_len);
        free(out);
    } else {
        ssl_send_str(ssl, "Error: Failed to execute command.\n");
    }
}

/* ------------------------------------------------------------------ */
/*  인증                                                                */
/* ------------------------------------------------------------------ */

char *get_username(void) {
    const char *username = getlogin();
    if (username == NULL) username = "unknown";
    char *ret = malloc(strlen(username) + 1);
    if (ret) strcpy(ret, username);
    return ret;
}

int is_valid_login(char *username, char *passwd, const char *server_passwd_hash) {
    if (username == NULL || passwd == NULL || server_passwd_hash == NULL) return -1;

    char *target_username = get_username();
    int is_user_valid = (strcmp(username, target_username) == 0);
    free(target_username);

    if (is_user_valid && verify_password(passwd, server_passwd_hash)) return 0;
    return -1;
}

/* ------------------------------------------------------------------ */
/*  클라이언트 요청 처리                                                */
/* ------------------------------------------------------------------ */

void handle_client_request(SSL *ssl, char *buffer, const char *username) {
    char log_message[BUF_SIZE + 100] = {0};

    if (strlen(buffer) == 0) return;

    snprintf(log_message, sizeof(log_message), "[%s] Received: %s", username, buffer);
    display_server_log(log_message);

    /* ── trace <user> ─────────────────────────────────────────────── */
    if (strncmp(buffer, "trace ", 6) == 0) {
        char *target_user = buffer + 6;
        target_user[strcspn(target_user, "\n")] = '\0';

        if (!is_valid_username(target_user)) {
            ssl_send_str(ssl, "Error: Invalid username.\n");
            display_server_log("Trace rejected: invalid username");
            return;
        }

        snprintf(log_message, sizeof(log_message),
                 "[%s] Executing trace for: %s", username, target_user);
        display_server_log(log_message);

        char *args[] = {"/usr/bin/renux", "trace", target_user, NULL};
        exec_and_send(ssl, "/usr/bin/renux", args);

        display_server_log("Trace result sent to client.");
        return;
    }

    /* ── get_fstab_quota_list ─────────────────────────────────────── */
    if (strcmp(buffer, "get_fstab_quota_list") == 0) {
        snprintf(log_message, sizeof(log_message),
                 "[%s] Executing: get_fstab_quota_list", username);
        display_server_log(log_message);

        FILE *fp = fopen("/etc/fstab", "r");
        if (fp == NULL) {
            ssl_send_str(ssl, "ERROR: Cannot open /etc/fstab\n");
        } else {
            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), fp)) {
                if (line[0] == '#' || line[0] == '\n') continue;
                if (strstr(line, "usrquota") != NULL) {
                    char fs_spec[100], fs_file[100];
                    sscanf(line, "%99s %99s", fs_spec, fs_file);
                    char mount_path[130];
                    int len = snprintf(mount_path, sizeof(mount_path), "%s\n", fs_file);
                    SSL_write(ssl, mount_path, len);
                }
            }
            fclose(fp);
        }
        ssl_send_str(ssl, "END_OF_LIST\n");
        display_server_log("Get fstab quota list method end");
        return;
    }

    /* ── user:method[:args...] ────────────────────────────────────── */
    if (strchr(buffer, ':')) {
        char temp_buffer[BUF_SIZE];
        strncpy(temp_buffer, buffer, BUF_SIZE - 1);
        temp_buffer[BUF_SIZE - 1] = '\0';

        char *parts[5] = {NULL};
        int i = 0;
        char *token = strtok(temp_buffer, ":");
        while (token != NULL && i < 5) {
            parts[i++] = token;
            token = strtok(NULL, ":");
        }

        char *target_username = parts[0];
        char *method          = parts[1];
        if (target_username == NULL || method == NULL) return;

        if (!is_valid_username(target_username)) {
            ssl_send_str(ssl, "Error: Invalid username.\n");
            snprintf(log_message, sizeof(log_message),
                     "[%s] Rejected: invalid username in request", username);
            display_server_log(log_message);
            return;
        }

        /* ── getinfo ──────────────────────────────────────────────── */
        if (strcmp(method, "getinfo") == 0) {
            snprintf(log_message, sizeof(log_message),
                     "[%s] Getting info for user: %s", username, target_username);
            display_server_log(log_message);

            struct passwd *user_info = getpwnam(target_username);
            if (user_info == NULL) {
                ssl_send_str(ssl, "Error: User not found.\n");
            } else {
                char info[BUF_SIZE];
                snprintf(info, BUF_SIZE,
                         "\n---- User Info: %s ----\n"
                         "  UID   : %u\n"
                         "  GID   : %u\n"
                         "  Home  : %s\n"
                         "  Shell : %s\n"
                         "----------------------\n",
                         user_info->pw_name, user_info->pw_uid,
                         user_info->pw_gid,  user_info->pw_dir,
                         user_info->pw_shell);
                SSL_write(ssl, info, (int)strlen(info));
                display_server_log("User info sent.");
            }
            return;
        }

        /* ── get_proc ─────────────────────────────────────────────── */
        if (strcmp(method, "get_proc") == 0) {
            snprintf(log_message, sizeof(log_message),
                     "[%s] Getting process list for: %s", username, target_username);
            display_server_log(log_message);

            char *args[] = {"/bin/ps", "-u", target_username, NULL};
            exec_and_send(ssl, "/bin/ps", args);
            ssl_send_str(ssl, "END_OF_LIST\n");
            display_server_log("Get process list end");
            return;
        }

        /* ── get_quota ────────────────────────────────────────────── */
        if (strcmp(method, "get_quota") == 0) {
            snprintf(log_message, sizeof(log_message),
                     "[%s] Getting quota for: %s", username, target_username);
            display_server_log(log_message);

            char *args[] = {"/usr/bin/quota", "-u", target_username, NULL};
            exec_and_send(ssl, "/usr/bin/quota", args);
            ssl_send_str(ssl, "END_OF_LIST\n");
            display_server_log("Get quota end");
            return;
        }

        /* ── set_quota ────────────────────────────────────────────── */
        if (strcmp(method, "set_quota") == 0) {
            char *soft_limit = parts[2];
            char *hard_limit = parts[3];
            char *filesystem = parts[4];

            if (!soft_limit || !hard_limit || !filesystem) {
                ssl_send_str(ssl, "Error: Missing quota parameters.\n");
                return;
            }
            if (!is_valid_quota_value(soft_limit)) {
                ssl_send_str(ssl, "Error: Invalid soft limit.\n"); return;
            }
            if (!is_valid_quota_value(hard_limit)) {
                ssl_send_str(ssl, "Error: Invalid hard limit.\n"); return;
            }
            if (!is_valid_filesystem(filesystem)) {
                ssl_send_str(ssl, "Error: Invalid filesystem path.\n"); return;
            }

            snprintf(log_message, sizeof(log_message),
                     "[%s] Setting quota for %s on %s: soft=%s hard=%s",
                     username, target_username, filesystem, soft_limit, hard_limit);
            display_server_log(log_message);

            char *args[] = {
                "/usr/sbin/setquota", "-u",
                target_username, soft_limit, hard_limit, "0", "0",
                filesystem, NULL
            };
            exec_and_send(ssl, "/usr/sbin/setquota", args);

            char result_msg[BUF_SIZE];
            snprintf(result_msg, sizeof(result_msg),
                     "Quota for %s on %s set.\n", target_username, filesystem);
            SSL_write(ssl, result_msg, (int)strlen(result_msg));
            ssl_send_str(ssl, "END_OF_LIST\n");
            display_server_log("Set quota end");
            return;
        }

        return;
    }

    /* ── exit ─────────────────────────────────────────────────────── */
    if (strcmp(buffer, "exit") == 0) {
        snprintf(log_message, sizeof(log_message), "[%s] disconnected.", username);
        display_server_log(log_message);
        SSL_shutdown(ssl);
        /* server.c 이벤트 루프가 EOF를 감지하여 SSL_free + close() 처리 */
        return;
    }

    /* ── getu: getpwent() 직접 호출 ──────────────────────────────── */
    if (strcmp(buffer, "getu") == 0) {
        snprintf(log_message, sizeof(log_message),
                 "[%s] Executing: getu", username);
        display_server_log(log_message);

        struct passwd *pw;
        char line[BUF_SIZE];
        setpwent();
        while ((pw = getpwent()) != NULL) {
            int len = snprintf(line, sizeof(line), "%s\n", pw->pw_name);
            if (len > 0 && len < BUF_SIZE) SSL_write(ssl, line, len);
        }
        endpwent();

        ssl_send_str(ssl, "END_OF_LIST\n");
        display_server_log("Get user end");
        return;
    }
}
