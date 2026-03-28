/**
 * renux (monitor.cpp) - V3.0
 * 변경사항 (V2 → V3):
 *   - inotify + /proc 폴링 제거 → eBPF syscall hook으로 대체
 *   - bashrc 훅 주입 제거 → eBPF execve tracepoint이 모든 쉘 실행 캡처
 *   - 탐지 지연 30초 → 0ms
 *   - 우회 불가 (syscall 진입점 후킹)
 *   - TLS 전송 / 오프라인 버퍼링 유지
 */

#include <iostream>
#include <fstream>
#include <string>
#include <queue>
#include <sstream>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <ctime>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <bpf/libbpf.h>
#include "renux.skel.h"
#include "renux_event.h"
#include "../utils/ssl_utils.h"

// --- 설정 및 상수 ---
const std::string AGENT_LOG_FILE = "/var/log/renux.log";
const std::string CONFIG_FILE    = "/etc/renux.conf";
const size_t OFFLINE_BUF_MAX     = 1000;


// --- 전역 변수 ---
volatile sig_atomic_t keep_running = 1;
const int RECONNECT_INTERVAL_SEC = 10;  /* master 재연결 시도 주기 */

std::string MY_IP     = "Unknown";
std::string MASTER_IP = "";
int MASTER_PORT       = 0;
int master_sock       = -1;
SSL_CTX *g_ssl_ctx    = nullptr;
SSL     *master_ssl   = nullptr;

std::mutex           net_mutex;
std::queue<std::string> offline_buffer;

// ─────────────────────────────────────────────────────────────────────
//  유틸리티
// ─────────────────────────────────────────────────────────────────────

std::string get_my_ip_address() {
    struct ifaddrs *ifaddr;
    char host[NI_MAXHOST];
    std::string found_ip = "127.0.0.1";

    if (getifaddrs(&ifaddr) == -1) return found_ip;
    for (auto *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
            std::string ip(host);
            if (ip != "127.0.0.1") { found_ip = ip; }
        }
    }
    freeifaddrs(ifaddr);
    return found_ip;
}

void load_config() {
    std::ifstream file(CONFIG_FILE);
    if (!file.is_open()) {
        std::cerr << "[Warning] Config not found: " << CONFIG_FILE << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string key, value;
        if (std::getline(ss, key, '=') && std::getline(ss, value)) {
            if (key == "MASTER_IP")        MASTER_IP   = value;
            else if (key == "MASTER_PORT") MASTER_PORT = std::stoi(value);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  네트워크 전송 (TLS + 오프라인 버퍼링)
// ─────────────────────────────────────────────────────────────────────

void connect_to_master() {
    if (MASTER_IP.empty() || MASTER_PORT == 0) return;
    if (master_sock != -1) return;

    master_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (master_sock < 0) { master_sock = -1; return; }

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(MASTER_PORT);
    if (inet_pton(AF_INET, MASTER_IP.c_str(), &serv_addr.sin_addr) <= 0) {
        close(master_sock); master_sock = -1; return;
    }
    if (connect(master_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(master_sock); master_sock = -1; return;
    }

    if (!g_ssl_ctx) g_ssl_ctx = create_client_ssl_ctx();
    if (!g_ssl_ctx) { close(master_sock); master_sock = -1; return; }

    master_ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(master_ssl, master_sock);
    if (SSL_connect(master_ssl) <= 0) {
        SSL_free(master_ssl); master_ssl = nullptr;
        close(master_sock); master_sock = -1; return;
    }

    std::string hello = "HELLO|" + MY_IP + "|Renux Agent V3 Started\n";
    SSL_write(master_ssl, hello.c_str(), (int)hello.length());
}

void send_log_to_master(const std::string& message) {
    if (MASTER_IP.empty()) return;

    std::lock_guard<std::mutex> lock(net_mutex);

    if (master_sock == -1) connect_to_master();

    if (master_sock == -1 || master_ssl == nullptr) {
        if (offline_buffer.size() >= OFFLINE_BUF_MAX) offline_buffer.pop();
        offline_buffer.push("LOG|" + MY_IP + "|" + message + "\n");
        return;
    }

    /* 재연결 성공 시 오프라인 버퍼 flush */
    while (!offline_buffer.empty()) {
        const std::string& buffered = offline_buffer.front();
        if (SSL_write(master_ssl, buffered.c_str(), (int)buffered.length()) <= 0) {
            SSL_free(master_ssl); master_ssl = nullptr;
            close(master_sock); master_sock = -1;
            offline_buffer.push("LOG|" + MY_IP + "|" + message + "\n");
            return;
        }
        offline_buffer.pop();
    }

    std::string packet = "LOG|" + MY_IP + "|" + message + "\n";
    if (SSL_write(master_ssl, packet.c_str(), (int)packet.length()) <= 0) {
        SSL_free(master_ssl); master_ssl = nullptr;
        close(master_sock); master_sock = -1;
        offline_buffer.push(packet);
    }
}

void write_agent_log(const std::string& message) {
    std::ofstream log_file(AGENT_LOG_FILE, std::ios::app);
    if (!log_file.is_open()) return;

    std::time_t now = std::time(nullptr);
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::string formatted = "[" + std::string(time_buf) + "] " + message;
    log_file << formatted << std::endl;

    send_log_to_master(formatted);
}

// ─────────────────────────────────────────────────────────────────────
//  eBPF 이벤트 콜백
// ─────────────────────────────────────────────────────────────────────

static int handle_event(void * /*ctx*/, void *data, size_t /*sz*/) {
    const struct renux_event *e = static_cast<const struct renux_event *>(data);

    switch (e->type) {
    case EVENT_EXEC: {
        std::string msg = "EXEC pid=" + std::to_string(e->pid) +
                          " uid=" + std::to_string(e->uid) +
                          " comm=" + e->comm +
                          " path=" + e->path;
        if (e->args[0] != '\0')
            msg += std::string(" args=") + e->args;
        write_agent_log(msg);
        break;
    }
    case EVENT_CONNECT: {
        struct in_addr addr;
        addr.s_addr = e->remote_ip;
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf));
        std::string msg = "ALERT: REVERSE_SHELL DETECTED | pid=" + std::to_string(e->pid) +
                          " comm=" + e->comm +
                          " remote=" + std::string(ip_buf) + ":" + std::to_string(ntohs(e->remote_port));
        write_agent_log(msg);
        break;
    }
    case EVENT_OPEN: {
        std::string msg = "FILE ACCESS: " + std::string(e->path) +
                          " by pid=" + std::to_string(e->pid) + "(" + e->comm + ")";
        write_agent_log(msg);
        break;
    }
    case EVENT_FORK: {
        std::string msg = "ALERT: WEBSHELL SUSPECTED | ppid=" + std::to_string(e->ppid) +
                          " -> child=" + e->comm + "(pid=" + std::to_string(e->pid) + ")";
        write_agent_log(msg);
        break;
    }
    default:
        break;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
//  기타
// ─────────────────────────────────────────────────────────────────────

void signal_handler(int /*sig*/) {
    keep_running = 0;
    /* SSL/소켓 정리는 main() 루프 종료 후 수행.
     * signal handler에서 async-signal-unsafe 함수 호출 금지. */
}

/* master 연결이 끊어졌을 때 주기적으로 재연결 시도 */
void reconnect_loop() {
    while (keep_running) {
        for (int i = 0; i < RECONNECT_INTERVAL_SEC && keep_running; i++)
            sleep(1);

        std::lock_guard<std::mutex> lock(net_mutex);
        if (master_sock == -1)
            connect_to_master();
    }
}

void handle_trace_command(const std::string& keyword) {
    std::ifstream file(AGENT_LOG_FILE);
    if (!file.is_open()) { std::cerr << "Cannot open log." << std::endl; return; }

    std::string line;
    std::cout << "--- Tracing: " << keyword << " ---" << std::endl;
    while (std::getline(file, line)) {
        if (line.find(keyword) != std::string::npos)
            std::cout << line << std::endl;
    }
    std::cout << "----------------------" << std::endl;
}

// ─────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "trace") {
        handle_trace_command(argc > 2 ? argv[2] : "");
        return 0;
    }

    load_config();
    MY_IP = get_my_ip_address();

    {
        std::ofstream test(AGENT_LOG_FILE, std::ios::app);
        if (!test.is_open()) { std::cerr << "Root required." << std::endl; return 1; }
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* eBPF 로드 및 attach */
    struct renux *skel = renux__open_and_load();
    if (!skel) {
        std::cerr << "[Error] Failed to load eBPF program. Kernel 5.8+ and CAP_BPF required." << std::endl;
        return 1;
    }

    if (renux__attach(skel) < 0) {
        std::cerr << "[Error] Failed to attach eBPF hooks." << std::endl;
        renux__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "[Error] Failed to create ring buffer." << std::endl;
        renux__destroy(skel);
        return 1;
    }

    write_agent_log("--- Monitoring Started (eBPF) on Agent [" + MY_IP + "] ---");
    connect_to_master();

    /* master 재연결 백그라운드 스레드 (10초마다 연결 끊기면 재시도) */
    std::thread(reconnect_loop).detach();

    /* 이벤트 루프: ring_buffer__poll은 100ms timeout으로 대기.
     * 이벤트 발생 시 즉시 handle_event 콜백 호출. */
    while (keep_running)
        ring_buffer__poll(rb, 100 /* ms */);

    ring_buffer__free(rb);
    renux__destroy(skel);

    if (master_ssl)  { SSL_shutdown(master_ssl); SSL_free(master_ssl); }
    if (g_ssl_ctx)   { SSL_CTX_free(g_ssl_ctx); }
    if (master_sock != -1) close(master_sock);

    write_agent_log("Monitoring Stopped.");
    return 0;
}
