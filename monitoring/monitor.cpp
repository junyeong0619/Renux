/**
 * renux (monitor.cpp) - V2.0
 * 변경사항:
 *   - popen("diff ...") 제거 → C++ 내장 line-diff로 대체
 *   - 오프라인 로그 버퍼링 (queue + mutex)
 *   - 리버스 쉘 탐지 스레드 (/proc/net/tcp)
 *   - 웹쉘 패턴 감지 (/proc/[pid]/stat)
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <signal.h>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "../utils/ssl_utils.h"

namespace fs = std::filesystem;

// --- 설정 및 상수 ---
const std::string AGENT_LOG_FILE  = "/var/log/renux.log";
const std::string CONFIG_FILE     = "/etc/renux.conf";
const std::string ROOT_HOME       = "/root";
const std::string USER_HOME_BASE  = "/home";
const off_t  MAX_BACKUP_SIZE  = 1024 * 1024;
const size_t MAX_BACKUP_COUNT = 500;
const size_t OFFLINE_BUF_MAX  = 1000;  // 오프라인 버퍼 최대 건수

// 리버스쉘 / 웹쉘 탐지 대상 프로세스명
const std::set<std::string> SHELL_NAMES   = {"bash","sh","dash","zsh","nc","ncat","python","python3","perl","ruby"};
const std::set<std::string> WEBSERVER_NAMES = {"httpd","apache2","nginx","lighttpd","php-fpm","php","uwsgi"};

// --- 전역 변수 ---
volatile sig_atomic_t keep_running = 1;
int inotify_fd;
std::map<int, std::string>   wd_to_path;
std::map<std::string, std::string> file_backups;
std::map<std::string, bool>  is_new_file;

// 마스터 인증서 경로 (TLS 검증용, SSL_VERIFY_NONE이므로 현재 미사용)
const std::string MASTER_CERT_PATH = "/etc/renux/master.crt";

// 네트워크 전역 변수
std::string MY_IP      = "Unknown";
std::string MASTER_IP  = "";
int MASTER_PORT        = 0;
int master_sock        = -1;
SSL_CTX *g_ssl_ctx     = nullptr;
SSL     *master_ssl    = nullptr;

// 오프라인 버퍼 (뮤텍스 보호)
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
    for (auto *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
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
            if (key == "MASTER_IP")   MASTER_IP   = value;
            else if (key == "MASTER_PORT") MASTER_PORT = std::stoi(value);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  네트워크 전송 (오프라인 버퍼링 포함)
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

    /* TLS 핸드셰이크 */
    if (!g_ssl_ctx) g_ssl_ctx = create_client_ssl_ctx_verified(MASTER_CERT_PATH.c_str());
    if (!g_ssl_ctx) { close(master_sock); master_sock = -1; return; }

    master_ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(master_ssl, master_sock);
    if (SSL_connect(master_ssl) <= 0) {
        SSL_free(master_ssl); master_ssl = nullptr;
        close(master_sock); master_sock = -1; return;
    }

    std::string hello = "HELLO|" + MY_IP + "|Renux Agent Started\n";
    SSL_write(master_ssl, hello.c_str(), (int)hello.length());
}

/*
 * 마스터 전송. 실패 시 offline_buffer에 누적.
 * 재연결 성공 시 버퍼 전체를 flush.
 */
void send_log_to_master(const std::string& message) {
    if (MASTER_IP.empty()) return;

    std::lock_guard<std::mutex> lock(net_mutex);

    // 재연결 시도
    if (master_sock == -1) connect_to_master();

    if (master_sock == -1 || master_ssl == nullptr) {
        // 오프라인 버퍼에 저장 (MAX 초과 시 가장 오래된 것 제거)
        if (offline_buffer.size() >= OFFLINE_BUF_MAX) offline_buffer.pop();
        offline_buffer.push("LOG|" + MY_IP + "|" + message + "\n");
        return;
    }

    // 재연결 성공 → 버퍼 flush 먼저
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

    // 현재 메시지 전송 (TLS)
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
    char time_buf[100];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::string formatted = "[" + std::string(time_buf) + "] " + message;
    log_file << formatted << std::endl;

    send_log_to_master(formatted);
}

// ─────────────────────────────────────────────────────────────────────
//  리버스 쉘 탐지 (/proc/net/tcp)
// ─────────────────────────────────────────────────────────────────────

// /proc/net/tcp 의 hex 주소를 IPv4 문자열로 변환
static std::string hex_to_ip(const std::string& hex) {
    unsigned long val = std::stoul(hex, nullptr, 16);
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = (uint32_t)val;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

// /proc/[pid]/comm 에서 프로세스 이름 읽기
static std::string get_proc_comm(const std::string& pid) {
    std::ifstream f("/proc/" + pid + "/comm");
    if (!f.is_open()) return "";
    std::string name;
    std::getline(f, name);
    // 개행/공백 제거
    name.erase(name.find_last_not_of(" \n\r\t") + 1);
    return name;
}

// /proc/[pid]/stat 에서 PPID 읽기 (세 번째 필드 이후 두 번째 값)
static std::string get_proc_ppid(const std::string& pid) {
    std::ifstream f("/proc/" + pid + "/stat");
    if (!f.is_open()) return "";
    std::string line;
    std::getline(f, line);
    // stat 형식: pid (comm) state ppid ...
    // ')'의 위치를 찾아 그 이후를 파싱
    size_t rp = line.rfind(')');
    if (rp == std::string::npos) return "";
    std::istringstream iss(line.substr(rp + 2));
    std::string state, ppid;
    iss >> state >> ppid;
    return ppid;
}

/*
 * /proc/net/tcp 를 파싱하여 외부로 연결된 소켓의 inode 목록을 반환
 * state==01 (ESTABLISHED), 원격 IP가 루프백이 아닌 것만
 */
static std::map<std::string, std::string> get_external_tcp_inodes() {
    std::map<std::string, std::string> inode_to_remote; // inode → remote_ip
    std::ifstream f("/proc/net/tcp");
    if (!f.is_open()) return inode_to_remote;

    std::string line;
    std::getline(f, line); // 헤더 스킵
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state, tx_rx, tr, retrnsmt, uid, timeout, inode;
        iss >> sl >> local >> remote >> state >> tx_rx >> tr >> retrnsmt >> uid >> timeout >> inode;

        if (state != "01") continue; // ESTABLISHED만

        // remote: "AABBCCDD:PORT" 형식
        size_t colon = remote.find(':');
        if (colon == std::string::npos) continue;
        std::string remote_ip = hex_to_ip(remote.substr(0, colon));

        if (remote_ip == "127.0.0.1" || remote_ip == "0.0.0.0") continue;

        inode_to_remote[inode] = remote_ip;
    }
    return inode_to_remote;
}

/*
 * /proc/[pid]/fd 에서 특정 inode를 가진 소켓을 찾으면 true
 */
static bool pid_has_inode(const std::string& pid, const std::string& target_inode) {
    std::string fd_dir = "/proc/" + pid + "/fd";
    DIR *dir = opendir(fd_dir.c_str());
    if (!dir) return false;

    char link_target[256];
    std::string socket_link = "socket:[" + target_inode + "]";

    struct dirent *entry;
    bool found = false;
    while ((entry = readdir(dir)) != NULL) {
        std::string fd_path = fd_dir + "/" + entry->d_name;
        ssize_t len = readlink(fd_path.c_str(), link_target, sizeof(link_target) - 1);
        if (len < 0) continue;
        link_target[len] = '\0';
        if (socket_link == link_target) { found = true; break; }
    }
    closedir(dir);
    return found;
}

void detect_reverse_shell() {
    auto tcp_inodes = get_external_tcp_inodes();
    if (tcp_inodes.empty()) return;

    // /proc 순회하여 각 PID가 해당 inode 소켓을 보유하는지 확인
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        std::string pid = entry->d_name;
        if (!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;

        std::string comm = get_proc_comm(pid);
        if (SHELL_NAMES.find(comm) == SHELL_NAMES.end()) continue;

        for (const auto& [inode, remote_ip] : tcp_inodes) {
            if (pid_has_inode(pid, inode)) {
                write_agent_log("ALERT: REVERSE_SHELL DETECTED | pid=" + pid
                                + " comm=" + comm
                                + " remote=" + remote_ip);
            }
        }
    }
    closedir(proc_dir);
}

// ─────────────────────────────────────────────────────────────────────
//  웹쉘 패턴 감지 (웹서버 → 쉘 자식 프로세스)
// ─────────────────────────────────────────────────────────────────────

void check_webshell_pattern() {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    // pid → comm 맵 먼저 구성
    std::map<std::string, std::string> pid_comm;
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        std::string pid = entry->d_name;
        if (!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;
        pid_comm[pid] = get_proc_comm(pid);
    }
    closedir(proc_dir);

    for (const auto& [pid, comm] : pid_comm) {
        if (SHELL_NAMES.find(comm) == SHELL_NAMES.end()) continue;

        std::string ppid = get_proc_ppid(pid);
        if (ppid.empty() || ppid == "1") continue;

        auto it = pid_comm.find(ppid);
        if (it == pid_comm.end()) continue;

        const std::string& parent_comm = it->second;
        if (WEBSERVER_NAMES.find(parent_comm) != WEBSERVER_NAMES.end()) {
            write_agent_log("ALERT: WEBSHELL SUSPECTED | parent=" + parent_comm
                            + "(pid=" + ppid + ") -> child=" + comm
                            + "(pid=" + pid + ")");
        }
    }
}

// 탐지 루프: 30초마다 실행
void detection_loop() {
    while (keep_running) {
        detect_reverse_shell();
        check_webshell_pattern();
        for (int i = 0; i < 30 && keep_running; i++) sleep(1);
    }
}

// ─────────────────────────────────────────────────────────────────────
//  기존 로직
// ─────────────────────────────────────────────────────────────────────

const std::string HOOK_MARKER = "# --- Renux Shell Logging Hook ---";
const std::string HOOK_SCRIPT = R"(
# --- Renux Shell Logging Hook ---
log_to_renux_history() {
    local hist_entry=$(history 1)
    local hist_num=$(echo "$hist_entry" | awk '{print $1}')
    local cmd=$(echo "$hist_entry" | sed "s/^[ ]*[0-9]*[ ]*//")
    local log_file="$HOME/.renux_history"
    local ts=$(date "+%a %b %d %H:%M:%S %Y")

    if [ "$hist_num" != "$LAST_RENUX_HIST_NUM" ] && [ -n "$cmd" ]; then
        if [ ! -f "$log_file" ]; then
            touch "$log_file"
            chmod 600 "$log_file"
        fi
        echo "[$ts] SHELL: $cmd" >> "$log_file"
        export LAST_RENUX_HIST_NUM="$hist_num"
    fi
}
export PROMPT_COMMAND="log_to_renux_history"
# --------------------------------
)";

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
    /* SSL/소켓 정리는 main() 루프 종료 후 수행.
     * signal handler에서 SSL_free 등 async-signal-unsafe 함수 호출 금지.
     * inotify read()가 EINTR을 받아 루프가 자연 종료된 후 cleanup 코드로 진입. */
}

std::string read_file_content(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buf;
    buf << file.rdbuf();
    return buf.str();
}

std::string read_last_line(const std::string& filename) {
    std::ifstream file(filename, std::ios::ate);
    if (!file.is_open()) return "";
    std::streampos pos = file.tellg();
    if (pos == 0) return "";
    int newline_count = 0;
    for (int i = 1; i <= (int)pos; i++) {
        file.seekg(-i, std::ios::end);
        char c = file.get();
        if (c == '\n') {
            newline_count++;
            if (newline_count == 2 || (newline_count == 1 && i > 1)) break;
        }
    }
    std::string last_line;
    std::getline(file, last_line);
    return last_line;
}

/*
 * popen("diff ...") 제거 → C++ 라인 비교로 대체
 * unified diff 형식(+/-) 으로 출력
 */
std::string generate_diff(const std::string& original, const std::string& current) {
    if (original == current) return "";

    auto split_lines = [](const std::string& s) {
        std::vector<std::string> lines;
        std::istringstream ss(s);
        std::string line;
        while (std::getline(ss, line)) lines.push_back(line);
        return lines;
    };

    std::vector<std::string> orig_lines = split_lines(original);
    std::vector<std::string> curr_lines = split_lines(current);

    std::ostringstream diff;
    diff << "--- original\n+++ modified\n";

    size_t o = 0, c = 0;
    while (o < orig_lines.size() || c < curr_lines.size()) {
        if (o < orig_lines.size() && c < curr_lines.size() &&
            orig_lines[o] == curr_lines[c]) {
            diff << " " << orig_lines[o] << "\n";
            o++; c++;
        } else {
            if (o < orig_lines.size()) diff << "-" << orig_lines[o++] << "\n";
            if (c < curr_lines.size()) diff << "+" << curr_lines[c++] << "\n";
        }
    }
    return diff.str();
}

void inject_hook_to_file(const std::string& home_dir) {
    fs::path bashrc_path = fs::path(home_dir) / ".bashrc";
    if (!fs::exists(bashrc_path)) {
        std::ofstream outfile(bashrc_path); outfile.close();
        fs::permissions(bashrc_path,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace);
    }
    std::ifstream file_in(bashrc_path);
    std::string line;
    bool found = false;
    if (file_in.is_open()) {
        while (std::getline(file_in, line)) {
            if (line.find(HOOK_MARKER) != std::string::npos) { found = true; break; }
        }
        file_in.close();
    }
    if (!found) {
        std::ofstream file_out(bashrc_path, std::ios::app);
        if (file_out.is_open()) {
            file_out << "\n" << HOOK_SCRIPT << "\n";
            write_agent_log("HOOK INJECTED: " + bashrc_path.string());
        }
    }
}

void setup_all_users_hooks() {
    write_agent_log("Checking Hooks...");
    inject_hook_to_file(ROOT_HOME);
    if (fs::exists(USER_HOME_BASE)) {
        for (const auto& entry : fs::directory_iterator(USER_HOME_BASE)) {
            if (entry.is_directory()) inject_hook_to_file(entry.path().string());
        }
    }
}

void add_watch_to_dir(const std::string& path) {
    int wd = inotify_add_watch(inotify_fd, path.c_str(),
        IN_MODIFY | IN_CREATE | IN_DELETE | IN_ISDIR |
        IN_OPEN   | IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd != -1) wd_to_path[wd] = path;
}

void add_watch_recursive(const std::string& root) {
    if (!fs::exists(root)) return;
    add_watch_to_dir(root);
    try {
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if (entry.is_directory()) add_watch_to_dir(entry.path().string());
        }
    } catch (...) {}
}

void handle_trace_command(const std::string& keyword) {
    std::ifstream file(AGENT_LOG_FILE);
    if (!file.is_open()) { std::cerr << "Cannot open log." << std::endl; return; }

    std::string line;
    std::cout << "--- Tracing: " << keyword << " ---" << std::endl;
    bool inside_diff_block = false;

    while (std::getline(file, line)) {
        if (!line.empty() && line[0] == '[') {
            if (line.find(keyword) != std::string::npos) {
                std::cout << line << std::endl;
                inside_diff_block = (line.find("FILE MODIFIED:") != std::string::npos);
            } else {
                inside_diff_block = false;
            }
        } else {
            if (inside_diff_block) std::cout << line << std::endl;
        }
    }
    std::cout << "----------------------" << std::endl;
}

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

    setup_all_users_hooks();

    inotify_fd = inotify_init();
    if (inotify_fd < 0) return 1;

    write_agent_log("--- Monitoring Started on Agent [" + MY_IP + "] ---");
    connect_to_master();

    add_watch_recursive(ROOT_HOME);
    if (fs::exists(USER_HOME_BASE)) {
        for (const auto& entry : fs::directory_iterator(USER_HOME_BASE)) {
            if (entry.is_directory()) add_watch_recursive(entry.path().string());
        }
    }

    // 탐지 스레드 시작
    std::thread(detection_loop).detach();

    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (keep_running) {
        ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
        if (len <= 0) break;

        const struct inotify_event *event;
        for (char *ptr = buffer; ptr < buffer + len;
             ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *)ptr;
            if (!event->len) continue;

            std::string dir_path = wd_to_path[event->wd];
            if (dir_path.empty()) continue;
            std::string full_path = dir_path + "/" + event->name;

            // 필터링
            if (full_path.find("renux.log")      != std::string::npos) continue;
            if (full_path.find(".swp")            != std::string::npos) continue;
            if (full_path.find(".swx")            != std::string::npos) continue;
            if (full_path.find(".viminfo")        != std::string::npos) continue;
            if (full_path.find("~")               != std::string::npos) continue;
            if (full_path.find("/.cache/")        != std::string::npos) continue;
            if (full_path.find("/abrt/")          != std::string::npos) continue;

            bool is_digit_only = true;
            for (char c : std::string(event->name)) if (!isdigit(c)) is_digit_only = false;
            if (is_digit_only) continue;

            if ((event->mask & IN_ISDIR) && (event->mask & IN_CREATE)) {
                add_watch_to_dir(full_path);
            } else if ((event->mask & IN_CREATE) && !(event->mask & IN_ISDIR)) {
                if (file_backups.size() > MAX_BACKUP_COUNT) file_backups.clear();
                file_backups[full_path] = "";
                is_new_file[full_path]  = true;
            } else if ((event->mask & IN_MODIFY) &&
                       full_path.find(".renux_history") != std::string::npos) {
                std::string content = read_last_line(full_path);
                if (!content.empty()) write_agent_log("SHELL [" + full_path + "]: " + content);
            } else if (event->mask & IN_OPEN) {
                if (full_path.find(".renux_history") != std::string::npos) continue;
                if (event->mask & IN_ISDIR) continue;
                if (!is_new_file.count(full_path) && !file_backups.count(full_path)) {
                    if (file_backups.size() > MAX_BACKUP_COUNT) file_backups.clear();
                    if (fs::exists(full_path) && fs::file_size(full_path) < MAX_BACKUP_SIZE) {
                        file_backups[full_path] = read_file_content(full_path);
                    } else {
                        file_backups[full_path] = "";
                    }
                }
            } else if ((event->mask & IN_CLOSE_WRITE) || (event->mask & IN_MOVED_TO)) {
                if (full_path.find(".renux_history") != std::string::npos) continue;
                std::string original;
                if (file_backups.count(full_path)) original = file_backups[full_path];

                if (fs::exists(full_path)) {
                    std::string current = read_file_content(full_path);
                    if (original != current) {
                        std::string diff = generate_diff(original, current);
                        if (diff.empty()) diff = "[Change Detected] (identical diff)\n";
                        write_agent_log("FILE MODIFIED: " + full_path + "\n" + diff);
                        file_backups[full_path] = current;
                    }
                }
                if (is_new_file.count(full_path)) is_new_file.erase(full_path);
            }
        }
    }

    if (master_ssl)  { SSL_shutdown(master_ssl); SSL_free(master_ssl); }
    if (g_ssl_ctx)   { SSL_CTX_free(g_ssl_ctx); }
    if (master_sock != -1) close(master_sock);
    close(inotify_fd);
    write_agent_log("Monitoring Stopped.");
    return 0;
}
