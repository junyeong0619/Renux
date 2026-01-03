/**
 * renux (monitor.cpp) - Network Agent Version
 * - Auto IP Detection (Self-Identity)
 * - Config File Support (/etc/renux.conf)
 * - Real-time Socket Transmission
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <signal.h>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <sstream>

// 네트워크 관련 헤더 추가
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

namespace fs = std::filesystem;

// --- 설정 및 상수 ---
const std::string AGENT_LOG_FILE = "/var/log/renux.log";
const std::string CONFIG_FILE = "/etc/renux.conf";
const std::string ROOT_HOME = "/root";
const std::string USER_HOME_BASE = "/home";
const off_t MAX_BACKUP_SIZE = 1024 * 1024;
const size_t MAX_BACKUP_COUNT = 500;

// --- 전역 변수 ---
volatile sig_atomic_t keep_running = 1;
int inotify_fd;
std::map<int, std::string> wd_to_path;
std::map<std::string, std::string> file_backups;
std::map<std::string, bool> is_new_file;

// 네트워크 전역 변수
std::string MY_IP = "Unknown";
std::string MASTER_IP = "";
int MASTER_PORT = 0;
int master_sock = -1;

// --- [신규 기능] 내 IP 주소 가져오기 ---
std::string get_my_ip_address() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    std::string found_ip = "127.0.0.1";

    if (getifaddrs(&ifaddr) == -1) return found_ip;

    // 인터페이스를 순회하며 IPv4 주소 찾기
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4만
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s == 0) {
                std::string ip(host);
                // 로컬 루프백(127.0.0.1)은 제외하고 실제 IP 찾기
                if (ip != "127.0.0.1") {
                    found_ip = ip;
                    // eth0, ens33 등을 선호한다면 여기서 break 해도 됨
                }
            }
        }
    }
    freeifaddrs(ifaddr);
    return found_ip;
}

// --- [신규 기능] 설정 파일 읽기 ---
void load_config() {
    std::ifstream file(CONFIG_FILE);
    if (!file.is_open()) {
        std::cerr << "[Warning] Config file not found at " << CONFIG_FILE << ". Network disabled." << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string key, value;
        if (std::getline(ss, key, '=') && std::getline(ss, value)) {
            if (key == "MASTER_IP") MASTER_IP = value;
            else if (key == "MASTER_PORT") MASTER_PORT = std::stoi(value);
        }
    }
}

// --- [신규 기능] 마스터 서버 연결 ---
void connect_to_master() {
    if (MASTER_IP.empty() || MASTER_PORT == 0) return;
    if (master_sock != -1) return; // 이미 연결됨

    master_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (master_sock < 0) return;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(MASTER_PORT);

    if (inet_pton(AF_INET, MASTER_IP.c_str(), &serv_addr.sin_addr) <= 0) {
        close(master_sock); master_sock = -1; return;
    }

    if (connect(master_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        // 연결 실패 (조용히 넘어감 - 나중에 재시도)
        close(master_sock); master_sock = -1;
    } else {
        // 연결 성공 시 식별 패킷 전송
        std::string hello = "HELLO|" + MY_IP + "|Renux Agent Started\n";
        send(master_sock, hello.c_str(), hello.length(), 0);
    }
}

// --- [신규 기능] 로그 전송 (자동 재연결 포함) ---
void send_log_to_master(const std::string& message) {
    if (MASTER_IP.empty()) return;

    // 연결 끊겼으면 재연결 시도
    if (master_sock == -1) connect_to_master();
    if (master_sock == -1) return; // 여전히 실패하면 포기

    // 패킷 포맷: "LOG|내IP|메시지"
    std::string packet = "LOG|" + MY_IP + "|" + message + "\n";

    ssize_t sent = send(master_sock, packet.c_str(), packet.length(), MSG_NOSIGNAL);
    if (sent < 0) {
        // 전송 실패 시 소켓 닫고 다음번에 재연결 유도
        close(master_sock);
        master_sock = -1;
    }
}

// --- 기존 로그 함수 수정 ---
void write_agent_log(const std::string& message) {
    // 1. 로컬 파일 기록
    std::ofstream log_file(AGENT_LOG_FILE, std::ios::app);
    if (log_file.is_open()) {
        std::time_t now = std::time(nullptr);
        char time_buf[100];
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        std::string formatted_msg = "[" + std::string(time_buf) + "] " + message;
        log_file << formatted_msg << std::endl;

        // 2. [네트워크 전송] 마스터 서버로 쏘기
        send_log_to_master(formatted_msg);
    }
}

// --- 이하 기존 로직과 동일 ---
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
    keep_running = 0;
    if (master_sock != -1) close(master_sock); // 종료 시 소켓 정리
}

std::string read_file_content(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
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

std::string generate_diff(const std::string& original, const std::string& filepath) {
    std::string temp_path = "/tmp/renux_diff_temp";
    std::ofstream temp_file(temp_path);
    temp_file << original;
    temp_file.close();

    std::string cmd = "diff -u -N " + temp_path + " " + filepath + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "[Error] diff command failed.";

    std::stringstream diff_output;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        diff_output << buffer;
    }
    pclose(pipe);
    remove(temp_path.c_str());
    return diff_output.str();
}

void inject_hook_to_file(const std::string& home_dir) {
    fs::path bashrc_path = fs::path(home_dir) / ".bashrc";
    if (!fs::exists(bashrc_path)) {
        std::ofstream outfile(bashrc_path); outfile.close();
        fs::permissions(bashrc_path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    }
    std::ifstream file_in(bashrc_path);
    std::string line;
    bool found = false;
    if (file_in.is_open()) {
        while(std::getline(file_in, line)) {
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
        IN_MODIFY | IN_CREATE | IN_DELETE | IN_ISDIR | IN_OPEN | IN_CLOSE_WRITE | IN_MOVED_TO);
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
    // Trace 명령은 로컬 로그만 검색 (네트워크 X)
    std::ifstream file(AGENT_LOG_FILE);
    if (!file.is_open()) {
        std::cerr << "Cannot open log." << std::endl; return;
    }
    std::string line;
    std::cout << "--- Tracing: " << keyword << " ---" << std::endl;
    bool inside_diff_block = false;

    while (std::getline(file, line)) {
        if (line.size() > 0 && line[0] == '[') {
            if (line.find(keyword) != std::string::npos) {
                std::cout << line << std::endl;
                if (line.find("FILE MODIFIED:") != std::string::npos ||
                    line.find("FILE CHANGED") != std::string::npos) {
                    inside_diff_block = true;
                } else {
                    inside_diff_block = false;
                }
            } else { inside_diff_block = false; }
        } else {
            if (inside_diff_block) std::cout << line << std::endl;
        }
    }
    std::cout << "----------------------" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string cmd = argv[1];
        if (cmd == "trace") {
            handle_trace_command(argc > 2 ? argv[2] : "");
            return 0;
        }
    }

    // 1. 설정 로드 및 IP 확인
    load_config();
    MY_IP = get_my_ip_address();

    // 2. 초기 로그
    {
        std::ofstream test(AGENT_LOG_FILE, std::ios::app);
        if (!test.is_open()) { std::cerr << "Root required." << std::endl; return 1; }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    setup_all_users_hooks();

    inotify_fd = inotify_init();
    if (inotify_fd < 0) return 1;

    write_agent_log("--- Monitoring Started on Agent [" + MY_IP + "] ---");
    // 최초 연결 시도
    connect_to_master();

    add_watch_recursive(ROOT_HOME);
    if (fs::exists(USER_HOME_BASE)) {
        for (const auto& entry : fs::directory_iterator(USER_HOME_BASE)) {
            if (entry.is_directory()) add_watch_recursive(entry.path().string());
        }
    }

    char buffer[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));

    while (keep_running) {
        ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
        if (len <= 0) break;

        const struct inotify_event *event;
        for (char *ptr = buffer; ptr < buffer + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;
            if (event->len) {
                std::string dir_path = wd_to_path[event->wd];
                if (dir_path.empty()) continue;
                std::string full_path = dir_path + "/" + event->name;

                // 필터링
                if (full_path.find("renux.log") != std::string::npos) continue;
                if (full_path.find(".swp") != std::string::npos) continue;
                if (full_path.find(".swx") != std::string::npos) continue;
                if (full_path.find(".viminfo") != std::string::npos) continue;
                if (full_path.find("~") != std::string::npos) continue;
                if (full_path.find("/.cache/") != std::string::npos) continue;
                if (full_path.find("/abrt/") != std::string::npos) continue;

                bool is_digit_only = true;
                for(char c : std::string(event->name)) if(!isdigit(c)) is_digit_only = false;
                if(is_digit_only) continue;

                if (event->mask & IN_ISDIR && event->mask & IN_CREATE) {
                    add_watch_to_dir(full_path);
                }
                else if ((event->mask & IN_CREATE) && !(event->mask & IN_ISDIR)) {
                    if (file_backups.size() > MAX_BACKUP_COUNT) file_backups.clear();
                    file_backups[full_path] = "";
                    is_new_file[full_path] = true;
                }

                else if (event->mask & IN_MODIFY && full_path.find(".renux_history") != std::string::npos) {
                    std::string content = read_last_line(full_path);
                    if (!content.empty()) write_agent_log("SHELL [" + full_path + "]: " + content);
                }

                else if (event->mask & IN_OPEN) {
                    if (full_path.find(".renux_history") != std::string::npos) continue;
                    if (!(event->mask & IN_ISDIR)) {
                        if (is_new_file.count(full_path)) { }
                        else if (file_backups.count(full_path)) { }
                        else {
                            if (file_backups.size() > MAX_BACKUP_COUNT) file_backups.clear();
                            if (fs::exists(full_path) && fs::file_size(full_path) < MAX_BACKUP_SIZE) {
                                file_backups[full_path] = read_file_content(full_path);
                            } else {
                                file_backups[full_path] = "";
                            }
                        }
                    }
                }
                else if ((event->mask & IN_CLOSE_WRITE) || (event->mask & IN_MOVED_TO)) {
                    if (full_path.find(".renux_history") != std::string::npos) continue;
                    std::string original = "";
                    if (file_backups.count(full_path)) original = file_backups[full_path];

                    if (fs::exists(full_path)) {
                        std::string current = read_file_content(full_path);
                        if (original != current) {
                            std::string diff = generate_diff(original, full_path);
                            if (diff.empty()) diff = "[Change Detected] (No diff output)\n" + current;

                            write_agent_log("FILE MODIFIED: " + full_path + "\n" + diff);
                            file_backups[full_path] = current;
                        }
                    }
                    if (is_new_file.count(full_path)) is_new_file.erase(full_path);
                }
            }
        }
    }
    if (master_sock != -1) close(master_sock);
    close(inotify_fd);
    write_agent_log("Monitoring Stopped.");
    return 0;
}