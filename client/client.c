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
#include "../utils/ssl_utils.h"

#define BUF_SIZE 1024
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* 전역 TLS 세션 — 단일 서버 연결 */
static SSL *g_ssl = NULL;

volatile bool is_menu_mode = false;
char **menu_user_list = NULL;
int menu_user_count = 0;

volatile bool is_fs_list_mode = false;
char **quota_fs_list = NULL;
int quota_fs_count = 0;

volatile bool is_trace_mode = false;
WINDOW *g_trace_border_win  = NULL;
WINDOW *g_trace_content_win = NULL;

pthread_mutex_t menu_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    SSL        *ssl;
    ChatWindows wins;
} thread_args_t;

/* ------------------------------------------------------------------ */
/*  수신 스레드                                                         */
/* ------------------------------------------------------------------ */

static void *receive_handler(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    SSL        *ssl  = thread_args->ssl;
    ChatWindows wins = thread_args->wins;

    char recv_buffer[BUF_SIZE];
    char line_buffer[BUF_SIZE] = {0};
    int  line_len = 0;
    int  read_size;

    while ((read_size = SSL_read(ssl, recv_buffer, BUF_SIZE - 1)) > 0) {
        if (line_len + read_size >= BUF_SIZE) {
            pthread_mutex_lock(&menu_lock);
            display_chat_message(wins.recv_win, "system",
                                 "WARNING: Message too long, truncated.");
            pthread_mutex_unlock(&menu_lock);
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

            line_len = (int)strlen(newline_ptr + 1);
            memmove(line_buffer, newline_ptr + 1, line_len + 1);

            pthread_mutex_lock(&menu_lock);
            if (is_menu_mode) {
                if (strcmp(completed_line, "END_OF_LIST") == 0) {
                    is_menu_mode = false;
                } else {
                    menu_user_count++;
                    menu_user_list = realloc(menu_user_list,
                                             sizeof(char *) * menu_user_count);
                    menu_user_list[menu_user_count - 1] = strdup(completed_line);
                }
            } else if (is_fs_list_mode) {
                if (strcmp(completed_line, "END_OF_LIST") == 0) {
                    is_fs_list_mode = false;
                } else if (strncmp(completed_line, "ERROR:", 6) == 0) {
                    display_chat_message(wins.recv_win, "server", completed_line);
                } else {
                    quota_fs_count++;
                    quota_fs_list = realloc(quota_fs_list,
                                            sizeof(char *) * quota_fs_count);
                    quota_fs_list[quota_fs_count - 1] = strdup(completed_line);
                }
            } else if (is_trace_mode && g_trace_content_win != NULL) {
                wprintw(g_trace_content_win, "%s\n", completed_line);
                wrefresh(g_trace_content_win);
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

/* ------------------------------------------------------------------ */
/*  명령 핸들러                                                         */
/* ------------------------------------------------------------------ */

static void get_users_handler(ChatWindows *wins) {
    display_chat_message(wins->recv_win, "System",
                         "Requesting user list from server...");
    pthread_mutex_lock(&menu_lock);
    if (menu_user_list != NULL) {
        for (int i = 0; i < menu_user_count; i++) free(menu_user_list[i]);
        free(menu_user_list);
    }
    is_menu_mode    = true;
    menu_user_list  = NULL;
    menu_user_count = 0;
    pthread_mutex_unlock(&menu_lock);

    SSL_write(g_ssl, "getu", 4);
    display_chat_message(wins->recv_win, "System", "User list updated.");
}

void run_trace_mode(SSL *ssl, const char *user, ChatWindows *wins) {
    int height = LINES - 6;
    int width  = COLS  - 6;
    int starty = 3, startx = 3;

    pthread_mutex_lock(&menu_lock);

    g_trace_border_win = newwin(height, width, starty, startx);
    wbkgd(g_trace_border_win, COLOR_PAIR(1));
    box(g_trace_border_win, 0, 0);
    mvwprintw(g_trace_border_win, 0, 2,
              "[ Trace Activity: %s ] (Press 'q' to close)", user);
    wrefresh(g_trace_border_win);

    g_trace_content_win = newwin(height - 2, width - 2, starty + 1, startx + 1);
    wbkgd(g_trace_content_win, COLOR_PAIR(1));
    scrollok(g_trace_content_win, TRUE);
    wrefresh(g_trace_content_win);

    is_trace_mode = true;
    nodelay(g_trace_content_win, TRUE);
    keypad(g_trace_content_win, TRUE);

    pthread_mutex_unlock(&menu_lock);

    while (1) {
        int ch = wgetch(g_trace_content_win);
        if (ch == 'q') break;

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "trace %s", user);
        SSL_write(ssl, cmd, (int)strlen(cmd));

        for (int i = 0; i < 10; i++) {
            usleep(100000);
            ch = wgetch(g_trace_content_win);
            if (ch == 'q') goto exit_trace;
        }
    }

exit_trace:
    pthread_mutex_lock(&menu_lock);
    is_trace_mode = false;
    if (g_trace_content_win) { delwin(g_trace_content_win); g_trace_content_win = NULL; }
    if (g_trace_border_win)  { delwin(g_trace_border_win);  g_trace_border_win  = NULL; }
    pthread_mutex_unlock(&menu_lock);

    redraw_main_tui(wins);
}

static void manage_users_handler(ChatWindows *wins) {
    pthread_mutex_lock(&menu_lock);
    if (menu_user_list == NULL || menu_user_count == 0) {
        pthread_mutex_unlock(&menu_lock);
        display_chat_message(wins->recv_win, "System",
                             "User list is empty. Please run 'getu' first.");
        return;
    }

    is_menu_mode = false;
    pthread_mutex_unlock(&menu_lock);

    int choice = show_user_menu(menu_user_list, menu_user_count);
    char *selected_user = menu_user_list[choice - 1];

    int selection = user_manage_function_selections();
    char command_buf[BUF_SIZE];

    switch (selection) {
        case 0: {
            snprintf(command_buf, sizeof(command_buf), "%s:getinfo", selected_user);
            SSL_write(g_ssl, command_buf, (int)strlen(command_buf));
            break;
        }
        case 1: {
            snprintf(command_buf, sizeof(command_buf), "%s:get_proc", selected_user);
            SSL_write(g_ssl, command_buf, (int)strlen(command_buf));
            break;
        }
        case 2: {
            int quota_choice = disk_quota_menu();
            if (quota_choice == -1) break;

            if (quota_choice == 0) {
                snprintf(command_buf, sizeof(command_buf), "%s:get_quota", selected_user);
                SSL_write(g_ssl, command_buf, (int)strlen(command_buf));
            } else if (quota_choice == 1) {
                pthread_mutex_lock(&menu_lock);
                if (quota_fs_list != NULL) {
                    for (int i = 0; i < quota_fs_count; i++) free(quota_fs_list[i]);
                    free(quota_fs_list);
                }
                is_fs_list_mode = true;
                quota_fs_list   = NULL;
                quota_fs_count  = 0;
                pthread_mutex_unlock(&menu_lock);

                SSL_write(g_ssl, "get_fstab_quota_list",
                          (int)strlen("get_fstab_quota_list"));
                display_chat_message(wins->recv_win, "System",
                                     "Fetching available filesystems...");

                while (is_fs_list_mode) { sleep(1); }

                if (quota_fs_count == 0) {
                    display_chat_message(wins->recv_win, "System",
                                         "No usrquota filesystems found.");
                    redraw_main_tui(wins);
                    break;
                }

                int fs_choice = show_filesystem_menu(quota_fs_list, quota_fs_count);
                if (fs_choice == 0) break;
                char *selected_fs = quota_fs_list[fs_choice - 1];

                char soft_limit[50], hard_limit[50];
                get_client_input(wins->send_win, "Soft Limit: ", soft_limit, 49);
                get_client_input(wins->send_win, "Hard Limit: ", hard_limit, 49);

                snprintf(command_buf, sizeof(command_buf),
                         "%s:set_quota:%s:%s:%s",
                         selected_user, soft_limit, hard_limit, selected_fs);
                SSL_write(g_ssl, command_buf, (int)strlen(command_buf));
            }
            break;
        }
        case 3: {
            run_trace_mode(g_ssl, selected_user, wins);
            break;
        }
        default: break;
    }

    char msg[100];
    snprintf(msg, sizeof(msg), "Selected: %s  func: %d", selected_user, selection + 1);
    display_chat_message(wins->recv_win, "System", msg);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    ChatWindows wins;

    if (argc != 3) {
        printf("Usage: ./client_e <server_ip> <port>\n");
        return EXIT_FAILURE;
    }
    char *ipaddr = argv[1];
    char *port   = argv[2];

    init_client_tui(&wins);

    /* ── TCP 소켓 생성 및 연결 ───────────────────────────────────── */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        cleanup_client_tui(); return EXIT_FAILURE;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(atoi(port));
    if (inet_pton(AF_INET, ipaddr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address"); close(sock);
        cleanup_client_tui(); return EXIT_FAILURE;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed"); close(sock);
        cleanup_client_tui(); return EXIT_FAILURE;
    }

    /* ── TLS 핸드셰이크 ─────────────────────────────────────────── */
    SSL_CTX *ssl_ctx = create_client_ssl_ctx_verified("/etc/renux/server.crt");
    if (!ssl_ctx) {
        display_chat_message(wins.recv_win, "system", "TLS context creation failed.");
        close(sock); cleanup_client_tui(); return EXIT_FAILURE;
    }

    g_ssl = SSL_new(ssl_ctx);
    SSL_set_fd(g_ssl, sock);

    if (SSL_connect(g_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        display_chat_message(wins.recv_win, "system", "TLS handshake failed.");
        SSL_free(g_ssl); SSL_CTX_free(ssl_ctx);
        close(sock); cleanup_client_tui(); return EXIT_FAILURE;
    }

    display_chat_message(wins.recv_win, "system",
                         "Connected (TLS). Waiting for server...");

    /* ── 수신 스레드 시작 ───────────────────────────────────────── */
    pthread_t recv_thread;
    thread_args_t args;
    args.ssl  = g_ssl;
    args.wins = wins;

    if (likely(pthread_create(&recv_thread, NULL, receive_handler, &args) < 0)) {
        perror("Thread creation failed");
        SSL_shutdown(g_ssl); SSL_free(g_ssl); SSL_CTX_free(ssl_ctx);
        close(sock); cleanup_client_tui(); return EXIT_FAILURE;
    }

    /* ── 메인 입력 루프 ─────────────────────────────────────────── */
    while (1) {
        get_client_input(wins.send_win, "com: ", buffer, BUF_SIZE);

        if (strcmp(buffer, "getu") == 0) {
            get_users_handler(&wins);
            continue;
        }
        if (strcmp(buffer, "manage") == 0) {
            manage_users_handler(&wins);
            continue;
        }

        SSL_write(g_ssl, buffer, (int)strlen(buffer));

        if (strcmp(buffer, "exit") == 0) break;
    }

    SSL_shutdown(g_ssl);
    SSL_free(g_ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);
    cleanup_client_tui();
    return 0;
}
