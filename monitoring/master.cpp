/**
 * Renux Master Server - V2.0 (TLS)
 * - Multi-threaded Agent Handling
 * - TLS 1.2+ 암호화 수신 (SSL_accept + SSL_read)
 * - Command Shell: list, trace <IP>, all, exit
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <algorithm>
#include <set>
#include "../utils/ssl_utils.h"

#define PORT        9000
#define BUFFER_SIZE 4096

/* 마스터 서버 인증서 경로 */
#define MASTER_CERT "/etc/renux/master.crt"
#define MASTER_KEY  "/etc/renux/master.key"

// --- 전역 변수 ---
std::mutex  log_mutex;
std::mutex  clients_mutex;
const std::string MASTER_LOG_FILE = "central_renux.log";

std::set<std::string> connected_agents;
std::string target_ip_filter = "";

// --- 헬퍼 ---

void log_message(const std::string& ip, const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);

    // 파일에 무조건 기록
    std::ofstream file(MASTER_LOG_FILE, std::ios::app);
    if (file.is_open()) {
        file << "[Agent: " << ip << "] " << msg << std::endl;
    }

    // 화면 출력 (필터 적용)
    if (target_ip_filter.empty() || target_ip_filter == ip) {
        if (target_ip_filter == ip) {
            std::cout << "\033[1;31m>>> [" << ip << "]\033[0m " << msg << std::endl;
        } else {
            std::cout << "\033[1;32m[Agent: " << ip << "]\033[0m " << msg << std::endl;
        }
    }
}

void update_agent_status(const std::string& ip, bool connected) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    if (connected) {
        connected_agents.insert(ip);
        std::cout << "\033[1;34m[SYSTEM] New TLS Agent: " << ip << "\033[0m" << std::endl;
    } else {
        connected_agents.erase(ip);
        std::cout << "\033[1;34m[SYSTEM] Agent Disconnected: " << ip << "\033[0m" << std::endl;
    }
}

// --- 에이전트 핸들러 (스레드별 SSL 세션) ---

void handle_client(int client_socket, struct sockaddr_in client_addr, SSL_CTX *ssl_ctx) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string ip_str(client_ip);

    /* TLS 핸드셰이크 */
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cerr << "[TLS] Handshake failed from " << ip_str << std::endl;
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    update_agent_status(ip_str, true);

    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

        if (bytes_read <= 0) {
            update_agent_status(ip_str, false);
            break;
        }

        std::string raw_data(buffer);
        // 패킷 파싱: "LOG|IP|Message" 또는 "HELLO|IP|Message"
        size_t first_pipe  = raw_data.find('|');
        size_t second_pipe = raw_data.find('|', first_pipe + 1);

        if (first_pipe != std::string::npos && second_pipe != std::string::npos) {
            std::string content = raw_data.substr(second_pipe + 1);
            if (!content.empty() && content.back() == '\n') content.pop_back();
            log_message(ip_str, content);
        } else {
            log_message(ip_str, raw_data);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
}

// --- 명령어 쉘 스레드 ---

void command_shell() {
    std::string cmd_line;
    while (true) {
        std::getline(std::cin, cmd_line);
        if (cmd_line.empty()) continue;

        std::stringstream ss(cmd_line);
        std::string cmd, arg;
        ss >> cmd >> arg;

        if (cmd == "exit" || cmd == "quit") {
            std::cout << "Shutting down Master Server..." << std::endl;
            exit(0);
        } else if (cmd == "list") {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::cout << "--- Connected Agents (" << connected_agents.size() << ") ---" << std::endl;
            for (const auto& agent : connected_agents)
                std::cout << " - " << agent << std::endl;
            std::cout << "------------------------------" << std::endl;
        } else if (cmd == "trace") {
            if (arg.empty()) {
                std::cout << "Usage: trace <IP_ADDRESS>" << std::endl;
            } else {
                target_ip_filter = arg;
                std::cout << "🔍 [FILTER] Tracing: " << arg << std::endl;
            }
        } else if (cmd == "all" || cmd == "reset") {
            target_ip_filter = "";
            std::cout << "🌍 [FILTER CLEARED] Showing all agents." << std::endl;
        } else if (cmd == "help") {
            std::cout << "  list        : Show connected agents\n"
                      << "  trace <IP>  : Filter logs by agent IP\n"
                      << "  all         : Show all agent logs\n"
                      << "  exit        : Stop server\n";
        } else {
            std::cout << "Unknown command. Type 'help'." << std::endl;
        }
    }
}

// --- main ---

int main() {
    /* ── TLS 초기화 ──────────────────────────────────────────────── */
    SSL_CTX *ssl_ctx = create_server_ssl_ctx(MASTER_CERT, MASTER_KEY);
    if (!ssl_ctx) {
        std::cerr << "TLS init failed. Check " << MASTER_CERT << " & " << MASTER_KEY << std::endl;
        std::cerr << "Hint: Run setup.sh to generate certificates." << std::endl;
        return 1;
    }

    /* ── 소켓 바인딩 ─────────────────────────────────────────────── */
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); return 1;
    }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed"); return 1;
    }
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed"); return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "  Renux Master Server (TLS) on Port " << PORT << std::endl;
    std::cout << "  Cert: " << MASTER_CERT << std::endl;
    std::cout << "  Type 'help' for commands." << std::endl;
    std::cout << "========================================" << std::endl;

    std::thread(command_shell).detach();

    /* ── Accept 루프 ─────────────────────────────────────────────── */
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_socket < 0) { perror("Accept failed"); continue; }

        /* TLS 핸드셰이크는 handle_client 스레드 내부에서 수행 */
        std::thread(handle_client, new_socket, client_addr, ssl_ctx).detach();
    }

    SSL_CTX_free(ssl_ctx);
    return 0;
}
