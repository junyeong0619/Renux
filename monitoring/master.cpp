/**
 * Renux Master Server (Control Tower) - Interactive V2
 * - Features:
 * 1. Multi-threaded Agent Handling
 * 2. Command Shell (list, trace <IP>, all, exit)
 * 3. Real-time Log Filtering
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <algorithm>
#include <set>

#define PORT 9000
#define BUFFER_SIZE 4096

// --- 전역 변수 및 설정 ---
std::mutex log_mutex;
std::mutex clients_mutex;
const std::string MASTER_LOG_FILE = "central_renux.log";

// 현재 연결된 에이전트 목록 (IP)
std::set<std::string> connected_agents;

// 필터링 설정 (비어있으면 모든 로그 출력)
std::string target_ip_filter = "";

// --- 헬퍼 함수 ---

// 로그 기록 및 화면 출력 (필터링 적용)
void log_message(const std::string& ip, const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);

    // 1. 파일에는 무조건 저장 (증거 보존)
    std::ofstream file(MASTER_LOG_FILE, std::ios::app);
    if (file.is_open()) {
        file << "[Agent: " << ip << "] " << msg << std::endl;
    }

    // 2. 화면 출력은 필터링 규칙 따름
    // 필터가 없거나(All), 필터가 현재 IP와 일치할 때만 출력
    if (target_ip_filter.empty() || target_ip_filter == ip) {
        // [IP] 부분을 색상 처리하여 가독성 높임
        if (target_ip_filter == ip) {
            // 타겟 추적 중일 때는 더 눈에 띄게 (빨간색/강조)
            std::cout << "\033[1;31m>>> [" << ip << "]\033[0m " << msg << std::endl;
        } else {
            // 일반 출력 (초록색)
            std::cout << "\033[1;32m[Agent: " << ip << "]\033[0m " << msg << std::endl;
        }
    }
}

// 에이전트 관리 (연결/해제 시 목록 갱신)
void update_agent_status(const std::string& ip, bool connected) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    if (connected) {
        connected_agents.insert(ip);
        // 시스템 메시지는 강제로 출력 (필터 무시)
        std::cout << "\033[1;34m[SYSTEM] New Agent Connected: " << ip << "\033[0m" << std::endl;
    } else {
        connected_agents.erase(ip);
        std::cout << "\033[1;34m[SYSTEM] Agent Disconnected: " << ip << "\033[0m" << std::endl;
    }
}

// --- 네트워크 스레드 ---

void handle_client(int client_socket, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string ip_str(client_ip);

    update_agent_status(ip_str, true);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (bytes_read <= 0) {
            update_agent_status(ip_str, false);
            break;
        }

        std::string raw_data(buffer);
        // 패킷 파싱 (LOG|IP|Message)
        size_t first_pipe = raw_data.find('|');
        size_t second_pipe = raw_data.find('|', first_pipe + 1);

        if (first_pipe != std::string::npos && second_pipe != std::string::npos) {
            std::string content = raw_data.substr(second_pipe + 1);
            if (!content.empty() && content.back() == '\n') content.pop_back();
            log_message(ip_str, content);
        } else {
            log_message(ip_str, raw_data);
        }
    }
    close(client_socket);
}

// --- 사용자 입력(명령어) 처리 스레드 ---

void command_shell() {
    std::string cmd_line;
    while (true) {
        // 입력 대기 (로그 출력과 겹칠 수 있으므로 심플하게 처리)
        // std::cout << "Renux> "; // 프롬프트는 로그와 섞여서 지저분할 수 있으니 생략하거나 필요 시 사용

        std::getline(std::cin, cmd_line);
        if (cmd_line.empty()) continue;

        std::stringstream ss(cmd_line);
        std::string cmd, arg;
        ss >> cmd >> arg;

        if (cmd == "exit" || cmd == "quit") {
            std::cout << "Shutting down Master Server..." << std::endl;
            exit(0);
        }
        else if (cmd == "list") {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::cout << "--- Connected Agents (" << connected_agents.size() << ") ---" << std::endl;
            for (const auto& agent : connected_agents) {
                std::cout << " - " << agent << std::endl;
            }
            std::cout << "------------------------------" << std::endl;
        }
        else if (cmd == "trace") {
            if (arg.empty()) {
                std::cout << "Usage: trace <IP_ADDRESS>" << std::endl;
            } else {
                target_ip_filter = arg;
                std::cout << "🔍 [FILTER ACTIVATED] Tracing only: " << arg << std::endl;
                std::cout << "   (Other logs are still being saved to file)" << std::endl;
            }
        }
        else if (cmd == "all" || cmd == "reset") {
            target_ip_filter = "";
            std::cout << "🌍 [FILTER CLEARED] Showing logs from ALL agents." << std::endl;
        }
        else if (cmd == "help") {
            std::cout << "--- Commands ---" << std::endl;
            std::cout << "  list        : Show connected agents" << std::endl;
            std::cout << "  trace <IP>  : Show logs only from specific IP" << std::endl;
            std::cout << "  all         : Show logs from all agents" << std::endl;
            std::cout << "  exit        : Stop server" << std::endl;
        }
        else {
            std::cout << "Unknown command. Type 'help'." << std::endl;
        }
    }
}

// --- 메인 함수 ---

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); return 1;
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt"); return 1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed"); return 1;
    }
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed"); return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "🚀 Renux Master Server Started on Port " << PORT << std::endl;
    std::cout << "   Type 'help' for commands." << std::endl;
    std::cout << "========================================" << std::endl;

    // 명령어 처리 스레드 시작 (Detach)
    std::thread(command_shell).detach();

    // 네트워크 연결 수락 루프
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
            perror("Accept failed"); continue;
        }
        std::thread(handle_client, new_socket, client_addr).detach();
    }

    return 0;
}