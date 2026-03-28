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
#include <signal.h>
#include <netinet/in.h>
#include <sys/errno.h>

#include "tui.h"
#include "service.h"
#include "../utils/ssl_utils.h"
#include "../utils/log.h"
#ifdef __APPLE__
    #include <sys/event.h>
#elif __linux__
    #include <sys/epoll.h>
    #include <sys/capability.h>
    #include <sys/prctl.h>
#endif

#define PORT          8080
#define BUF_SIZE      1024
#define MAX_EVENTS    128
#define USERNAME_MAX_LEN 32

/* TLS 인증서 경로 */
#define SERVER_CERT "/etc/renux/server.crt"
#define SERVER_KEY  "/etc/renux/server.key"

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

volatile sig_atomic_t server_running = 1;

typedef struct {
    int   fd;
    SSL  *ssl;            /* 클라이언트별 TLS 세션 */
    int   is_logged_in;
    char  username[USERNAME_MAX_LEN];
    char  ip_addr[INET_ADDRSTRLEN];
    time_t last_activity;
} client_state;

void handle_sigint(int sig) { (void)sig; server_running = 0; }

static void generate_socket(int *server_fd) {
    int opt = 1;
    if ((*server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        display_server_log("Error: Socket generating failed");
        cleanup_server_tui(); exit(EXIT_FAILURE);
    }
    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static void get_server_password(char *server_passwd) {
    display_server_log("Set the password for Client accepting.");
    get_server_input(server_passwd, BUF_SIZE);
    display_server_log("Password save completed.");
}

/* 클라이언트 SSL 정리 */
static void cleanup_client(client_state *c) {
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd != -1) {
        close(c->fd);
        c->fd = -1;
    }
    c->is_logged_in = 0;
}

static void server_cleanup(int server_fd, char *username, SSL_CTX *ssl_ctx,
                           client_state *clients) {
    for (int i = 0; i < MAX_EVENTS; i++) {
        if (clients[i].fd != -1) cleanup_client(&clients[i]);
    }
    SSL_CTX_free(ssl_ctx);
    close(server_fd);
    display_server_log("Exiting Server...");
    sleep(1);
    cleanup_logger();
    cleanup_server_tui();
    free(username);
}

static void safe_log_message_concat(char *message, char *string, char *buffer) {
    snprintf(buffer, BUF_SIZE, string, message);
    display_server_log(buffer);
}

int main(int argc, char *argv[]) {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char log_message[BUF_SIZE + 100];
    char *username;
    int connected_clients = 0;

    /* -p <password> : 헤드리스 모드 (TUI 없이 실행, 테스트 전용) */
    char headless_passwd[BUF_SIZE] = {0};
    if (argc == 3 && strcmp(argv[1], "-p") == 0) {
        headless_mode = 1;
        strncpy(headless_passwd, argv[2], BUF_SIZE - 1);
    }

    signal(SIGINT, handle_sigint);

    username = get_username();
    init_server_tui();
    init_logger("server.log");
    update_client_count(connected_clients);

    /* ── TLS 초기화 ──────────────────────────────────────────────── */
    SSL_CTX *ssl_ctx = create_server_ssl_ctx(SERVER_CERT, SERVER_KEY);
    if (!ssl_ctx) {
        display_server_log("Error: TLS init failed. Check /etc/renux/server.crt & server.key");
        display_server_log("Hint: Run setup.sh to generate certificates.");
        cleanup_server_tui();
        exit(EXIT_FAILURE);
    }
    display_server_log("[TLS] Context initialized (TLS 1.2+)");

    /* ── 소켓 생성 / 바인딩 / 리스닝 ────────────────────────────── */
    generate_socket(&server_fd);
    display_server_log("Server socket generated");

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);

    if (likely(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)) {
        display_server_log("Error: Binding failed");
        cleanup_server_tui(); exit(EXIT_FAILURE);
    }
    display_server_log("Server binding succeeded");

    if (likely(listen(server_fd, 3) < 0)) {
        display_server_log("Error: Listening failed");
        cleanup_server_tui(); exit(EXIT_FAILURE);
    }
    display_server_log("Server Listening... Waiting for client connection.");

    safe_log_message_concat(username, "\tnow opened server.", log_message);

    /* ── 비밀번호 해싱 (SHA-256) ─────────────────────────────────── */
    char server_passwd_plain[BUF_SIZE];
    if (headless_mode)
        strncpy(server_passwd_plain, headless_passwd, BUF_SIZE - 1);
    else
        get_server_password(server_passwd_plain);

    char server_passwd_hash[98];
    hash_password_salted(server_passwd_plain, server_passwd_hash);
    memset(server_passwd_plain, 0, sizeof(server_passwd_plain));

    char hashed_msg[100];
    snprintf(hashed_msg, sizeof(hashed_msg),
             "Password hashed (PBKDF2-SHA256): %.16s...", server_passwd_hash);
    display_server_log(hashed_msg);

    /* ── kqueue / epoll 초기화 ───────────────────────────────────── */
#ifdef __APPLE__
    int kq = kqueue();
    if (kq == -1) { perror("kqueue"); exit(EXIT_FAILURE); }
    struct kevent change_event;
    struct kevent event_list[MAX_EVENTS];
#elif __linux__
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) { perror("epoll_create1"); exit(EXIT_FAILURE); }
    struct epoll_event event, events[MAX_EVENTS];
#endif

    client_state clients[MAX_EVENTS];
    for (int i = 0; i < MAX_EVENTS; i++) {
        clients[i].fd  = -1;
        clients[i].ssl = NULL;
        clients[i].is_logged_in = 0;
    }

#ifdef __APPLE__
    EV_SET(&change_event, server_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (kevent(kq, &change_event, 1, NULL, 0, NULL) == -1) {
        perror("kevent register"); exit(EXIT_FAILURE);
    }
#elif __linux__
    event.events  = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
        perror("epoll_ctl"); exit(EXIT_FAILURE);
    }
#endif

    /* ── Privilege Drop (Linux only) ─────────────────────────────── */
#ifdef __linux__
    {
        cap_t caps = cap_init();
        if (caps != NULL) {
            if (cap_set_proc(caps) == 0)
                display_server_log("[Hardening] All capabilities dropped.");
            else
                display_server_log("[Hardening] Warning: cap_set_proc failed.");
            cap_free(caps);
        }
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
#endif

    display_server_log("Server is running with TLS event loop...");

    /* ── 이벤트 루프 ─────────────────────────────────────────────── */
    while (server_running) {
#ifdef __APPLE__
        struct timespec timeout = {1, 0};
        int num_events = kevent(kq, NULL, 0, event_list, MAX_EVENTS, &timeout);
#elif __linux__
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
#endif

        if (num_events == -1) {
            if (errno == EINTR) continue;
#ifdef __APPLE__
            perror("kevent wait");
#elif __linux__
            perror("epoll_wait");
#endif
            break;
        }

        for (int i = 0; i < num_events; i++) {
#ifdef __APPLE__
            int event_fd = (int)event_list[i].ident;
#elif __linux__
            int event_fd = events[i].data.fd;
#endif

            /* ── 클라이언트 연결 해제 ──────────────────────────── */
#ifdef __APPLE__
            if (event_list[i].flags & EV_EOF) {
#elif __linux__
            if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
#endif
                display_server_log("Client disconnected.");
                connected_clients--;
                update_client_count(connected_clients);
                for (int j = 0; j < MAX_EVENTS; j++) {
                    if (clients[j].fd == event_fd) {
                        cleanup_client(&clients[j]);
                        break;
                    }
                }

            /* ── 신규 클라이언트 접속 ──────────────────────────── */
            } else if (event_fd == server_fd) {
                int client_socket = accept(server_fd,
                                           (struct sockaddr *)&address,
                                           (socklen_t *)&addrlen);
                if (client_socket == -1) { perror("accept"); continue; }

                /* TLS 핸드셰이크 */
                SSL *client_ssl = SSL_new(ssl_ctx);
                SSL_set_fd(client_ssl, client_socket);
                if (SSL_accept(client_ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    display_server_log("TLS handshake failed. Client rejected.");
                    SSL_free(client_ssl);
                    close(client_socket);
                    continue;
                }

#ifdef __APPLE__
                EV_SET(&change_event, client_socket, EVFILT_READ, EV_ADD, 0, 0, 0);
                kevent(kq, &change_event, 1, NULL, 0, NULL);
#elif __linux__
                event.events  = EPOLLIN | EPOLLET;
                event.data.fd = client_socket;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &event) == -1) {
                    perror("epoll_ctl");
                    SSL_shutdown(client_ssl); SSL_free(client_ssl);
                    close(client_socket);
                    continue;
                }
#endif

                for (int j = 0; j < MAX_EVENTS; j++) {
                    if (clients[j].fd == -1) {
                        clients[j].fd  = client_socket;
                        clients[j].ssl = client_ssl;
                        if (address.sin_family == AF_INET)
                            inet_ntop(AF_INET, &address.sin_addr,
                                      clients[j].ip_addr, INET_ADDRSTRLEN);
                        break;
                    }
                }

                display_server_log("New TLS client connected.");
                const char *login_msg =
                    "Put the login information in this form: username,password";
                SSL_write(client_ssl, login_msg, (int)strlen(login_msg));

            /* ── 기존 클라이언트 데이터 수신 ───────────────────── */
            } else {
                char buffer[BUF_SIZE] = {0};

                /* SSL* 조회 */
                client_state *current_client = NULL;
                for (int j = 0; j < MAX_EVENTS; j++) {
                    if (clients[j].fd == event_fd) {
                        current_client = &clients[j];
                        break;
                    }
                }
                if (current_client == NULL || current_client->ssl == NULL) continue;

                int valread = SSL_read(current_client->ssl, buffer, BUF_SIZE - 1);
                if (valread <= 0) {
                    /* 연결 종료 또는 TLS 오류 */
                    display_server_log("Client disconnected (SSL_read).");
                    connected_clients--;
                    update_client_count(connected_clients);
                    cleanup_client(current_client);
                    continue;
                }

                buffer[valread] = '\0';
                buffer[strcspn(buffer, "\n")] = 0;

                if (current_client->is_logged_in) {
                    handle_client_request(current_client->ssl, buffer,
                                          current_client->username);
                } else {
                    char data[BUF_SIZE];
                    strncpy(data, buffer, BUF_SIZE - 1);
                    char *recv_username = strtok(data, ",");
                    char *password      = strtok(NULL, ",");

                    if (recv_username && password &&
                        is_valid_login(recv_username, password, server_passwd_hash) == 0) {
                        current_client->is_logged_in = 1;
                        connected_clients++;
                        update_client_count(connected_clients);
                        strncpy(current_client->username, recv_username,
                                USERNAME_MAX_LEN - 1);

                        SSL_write(current_client->ssl, "logsuc", 6);
                        display_server_log("Client login successful.");

                        char log_buf[256];
                        snprintf(log_buf, sizeof(log_buf),
                                 "Login: %s@%s",
                                 current_client->username, current_client->ip_addr);
                        display_server_log(log_buf);
                    } else {
                        SSL_write(current_client->ssl, "Login failed", 12);
                        display_server_log("Client login failed.");
                    }
                }
            }
        }
    }

    server_cleanup(server_fd, username, ssl_ctx, clients);
    return 0;
}
