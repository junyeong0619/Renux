/**
 * Renux Master Server - V2.1 (TLS + TUI Dashboard)
 * - Multi-threaded agent handling
 * - TLS 1.2+ encrypted reception
 * - Commands: list, trace <IP>, all, tm, exit
 * - tm: ncurses dashboard with per-agent panels, alert highlighting
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <deque>
#include <map>
#include <thread>
#include <mutex>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <algorithm>
#include <set>
#include <ncurses.h>
#include "../utils/ssl_utils.h"

#define PORT         9000
#define BUFFER_SIZE  4096
#define MAX_LOG_LINES 200

#define MASTER_CERT "/etc/renux/master.crt"
#define MASTER_KEY  "/etc/renux/master.key"

/* ncurses color pair IDs */
#define CP_BORDER_NORMAL  1   /* white */
#define CP_BORDER_ALERT   2   /* red   */
#define CP_TITLE_NORMAL   3   /* cyan  */
#define CP_TITLE_ALERT    4   /* red bold */
#define CP_LINE_ALERT     5   /* yellow */
#define CP_STATUSBAR      6   /* reversed */
#define CP_SELECTED       7   /* green */

// ─────────────────────────────────────────────────────────────────────
//  전역 상태
// ─────────────────────────────────────────────────────────────────────

struct AgentData {
    std::deque<std::string> logs;  /* 최근 MAX_LOG_LINES 라인 */
    bool alert = false;            /* ALERT: 포함 로그 수신 시 true */
};

std::mutex log_mutex;
std::mutex clients_mutex;
std::mutex agent_data_mutex;
const std::string MASTER_LOG_FILE = "central_renux.log";

std::set<std::string>            connected_agents;
std::map<std::string, AgentData> agent_data;
std::string target_ip_filter = "";
bool        dashboard_active  = false;

// ─────────────────────────────────────────────────────────────────────
//  로그 기록 & 상태 업데이트
// ─────────────────────────────────────────────────────────────────────

void log_message(const std::string& ip, const std::string& msg) {
    /* 파일 기록 */
    {
        std::lock_guard<std::mutex> lk(log_mutex);
        std::ofstream f(MASTER_LOG_FILE, std::ios::app);
        if (f.is_open())
            f << "[Agent: " << ip << "] " << msg << "\n";
    }

    /* per-agent 버퍼 업데이트 */
    {
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        auto& d = agent_data[ip];
        d.logs.push_back(msg);
        if (d.logs.size() > MAX_LOG_LINES) d.logs.pop_front();
        if (msg.find("ALERT:") != std::string::npos) d.alert = true;
    }

    /* 콘솔 출력 (대시보드 활성 중에는 억제) */
    if (!dashboard_active) {
        std::lock_guard<std::mutex> lk(log_mutex);
        if (target_ip_filter.empty() || target_ip_filter == ip) {
            if (target_ip_filter == ip)
                std::cout << "\033[1;31m>>> [" << ip << "]\033[0m " << msg << "\n";
            else
                std::cout << "\033[1;32m[Agent: " << ip << "]\033[0m " << msg << "\n";
        }
    }
}

void update_agent_status(const std::string& ip, bool connected) {
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        if (connected) connected_agents.insert(ip);
        else           connected_agents.erase(ip);
    }
    {
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        if (connected) agent_data[ip];  /* entry 생성 */
    }
    if (!dashboard_active) {
        std::lock_guard<std::mutex> lk(log_mutex);
        if (connected)
            std::cout << "\033[1;34m[SYSTEM] New TLS Agent: " << ip << "\033[0m\n";
        else
            std::cout << "\033[1;34m[SYSTEM] Agent Disconnected: " << ip << "\033[0m\n";
    }
}

// ─────────────────────────────────────────────────────────────────────
//  TUI Dashboard
// ─────────────────────────────────────────────────────────────────────

struct PanelLayout { int y, x, h, w; };

static std::vector<PanelLayout> calc_layout(int n, int rows, int cols) {
    int usable = rows - 1;  /* 하단 1행: 상태바 */
    std::vector<PanelLayout> L;

    if (n == 1) {
        L.push_back({0, 0, usable, cols});
    } else if (n == 2) {
        int hw = cols / 2;
        L.push_back({0, 0,  usable, hw});
        L.push_back({0, hw, usable, cols - hw});
    } else if (n == 3) {
        int hh = usable / 2, hw = cols / 2;
        L.push_back({0,  0,  hh,          hw});
        L.push_back({0,  hw, hh,          cols - hw});
        L.push_back({hh, 0,  usable - hh, cols});
    } else {  /* 4 */
        int hh = usable / 2, hw = cols / 2;
        L.push_back({0,  0,  hh,          hw});
        L.push_back({0,  hw, hh,          cols - hw});
        L.push_back({hh, 0,  usable - hh, hw});
        L.push_back({hh, hw, usable - hh, cols - hw});
    }
    return L;
}

static void draw_panel(WINDOW *win, const std::string& ip,
                       const std::deque<std::string>& logs, bool alert) {
    int h, w;
    getmaxyx(win, h, w);
    werase(win);

    /* 테두리 */
    wattron(win, COLOR_PAIR(alert ? CP_BORDER_ALERT : CP_BORDER_NORMAL) | (alert ? A_BOLD : 0));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(CP_BORDER_ALERT) | COLOR_PAIR(CP_BORDER_NORMAL) | A_BOLD);

    /* 타이틀 */
    std::string title = alert ? (" !! " + ip + " !! ") : (" " + ip + " ");
    int tx = std::max(1, (w - (int)title.size()) / 2);
    wattron(win, COLOR_PAIR(alert ? CP_TITLE_ALERT : CP_TITLE_NORMAL) | A_BOLD);
    mvwprintw(win, 0, tx, "%s", title.c_str());
    wattroff(win, COLOR_PAIR(CP_TITLE_ALERT) | COLOR_PAIR(CP_TITLE_NORMAL) | A_BOLD);

    /* 로그 라인 */
    int ch = h - 2, cw = w - 2;
    int start = (int)logs.size() > ch ? (int)logs.size() - ch : 0;

    for (int i = 0; i < ch && start + i < (int)logs.size(); i++) {
        std::string line = logs[start + i];
        if ((int)line.size() > cw) line = line.substr(0, cw);

        bool is_alert = line.find("ALERT:") != std::string::npos;
        if (is_alert) wattron(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
        mvwprintw(win, i + 1, 1, "%-*s", cw, line.c_str());
        if (is_alert) wattroff(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
    }

    wrefresh(win);
}

static void draw_statusbar(int rows, int cols, int n_agents, int n_alerts) {
    char tbuf[32];
    time_t now = time(nullptr);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    std::string left  = std::string(" ") + tbuf +
                        "  Agents: " + std::to_string(n_agents);
    std::string right = "Alerts: " + std::to_string(n_alerts) +
                        "  [c]lear  [q]uit ";

    int pad = cols - (int)left.size() - (int)right.size();
    std::string bar = left + std::string(std::max(0, pad), ' ') + right;
    if ((int)bar.size() > cols) bar = bar.substr(0, cols);

    attron(COLOR_PAIR(CP_STATUSBAR) | A_REVERSE);
    mvprintw(rows - 1, 0, "%s", bar.c_str());
    attroff(COLOR_PAIR(CP_STATUSBAR) | A_REVERSE);
    refresh();
}

static void run_dashboard(const std::vector<std::string>& ips) {
    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(500);

    init_pair(CP_BORDER_NORMAL, COLOR_WHITE,  COLOR_BLACK);
    init_pair(CP_BORDER_ALERT,  COLOR_RED,    COLOR_BLACK);
    init_pair(CP_TITLE_NORMAL,  COLOR_CYAN,   COLOR_BLACK);
    init_pair(CP_TITLE_ALERT,   COLOR_RED,    COLOR_BLACK);
    init_pair(CP_LINE_ALERT,    COLOR_YELLOW, COLOR_BLACK);
    init_pair(CP_STATUSBAR,     COLOR_BLACK,  COLOR_WHITE);
    init_pair(CP_SELECTED,      COLOR_GREEN,  COLOR_BLACK);

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int n = std::min((int)ips.size(), 4);
    auto layouts = calc_layout(n, rows, cols);

    std::vector<WINDOW*> wins;
    for (int i = 0; i < n; i++) {
        auto& L = layouts[i];
        wins.push_back(newwin(L.h, L.w, L.y, L.x));
    }

    while (true) {
        int ch = getch();

        if (ch == 'q' || ch == 'Q') break;

        if (ch == 'c' || ch == 'C') {
            std::lock_guard<std::mutex> lk(agent_data_mutex);
            for (auto& ip : ips)
                if (agent_data.count(ip)) agent_data[ip].alert = false;
        }

        if (ch == KEY_RESIZE) {
            getmaxyx(stdscr, rows, cols);
            for (auto w : wins) delwin(w);
            wins.clear();
            layouts = calc_layout(n, rows, cols);
            for (int i = 0; i < n; i++) {
                auto& L = layouts[i];
                wins.push_back(newwin(L.h, L.w, L.y, L.x));
            }
            clear(); refresh();
        }

        int n_alerts = 0;
        for (int i = 0; i < n; i++) {
            std::deque<std::string> logs_copy;
            bool alert = false;
            {
                std::lock_guard<std::mutex> lk(agent_data_mutex);
                if (agent_data.count(ips[i])) {
                    logs_copy = agent_data[ips[i]].logs;
                    alert     = agent_data[ips[i]].alert;
                }
            }
            if (alert) n_alerts++;
            draw_panel(wins[i], ips[i], logs_copy, alert);
        }
        draw_statusbar(rows, cols, n, n_alerts);
    }

    for (auto w : wins) delwin(w);
    endwin();
}

// ─────────────────────────────────────────────────────────────────────
//  에이전트 선택 화면 (ncurses)
// ─────────────────────────────────────────────────────────────────────

static std::vector<std::string> select_agents_tui() {
    std::vector<std::string> all;
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        all.assign(connected_agents.begin(), connected_agents.end());
    }
    if (all.empty()) {
        std::cout << "[tm] No connected agents.\n";
        return {};
    }

    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    init_pair(CP_SELECTED,     COLOR_GREEN, COLOR_BLACK);
    init_pair(CP_TITLE_NORMAL, COLOR_CYAN,  COLOR_BLACK);

    std::vector<bool> checked(all.size(), false);
    int cursor = 0;

    while (true) {
        clear();
        attron(COLOR_PAIR(CP_TITLE_NORMAL) | A_BOLD);
        mvprintw(0, 2, "Trace Monitor — Select agents (max 4)");
        attroff(COLOR_PAIR(CP_TITLE_NORMAL) | A_BOLD);
        mvprintw(1, 2, "UP/DOWN: move  SPACE: toggle  a: all  ENTER: confirm  q: cancel");

        for (int i = 0; i < (int)all.size(); i++) {
            if (i == cursor) attron(A_REVERSE);
            if (checked[i]) {
                attron(COLOR_PAIR(CP_SELECTED));
                mvprintw(i + 3, 4, "[x] %s", all[i].c_str());
                attroff(COLOR_PAIR(CP_SELECTED));
            } else {
                mvprintw(i + 3, 4, "[ ] %s", all[i].c_str());
            }
            if (i == cursor) attroff(A_REVERSE);
        }
        refresh();

        int ch = getch();
        switch (ch) {
        case KEY_UP:   cursor = std::max(0, cursor - 1); break;
        case KEY_DOWN: cursor = std::min((int)all.size() - 1, cursor + 1); break;
        case ' ':      checked[cursor] = !checked[cursor]; break;
        case 'a': case 'A':
            std::fill(checked.begin(), checked.end(), true);
            break;
        case '\n': case KEY_ENTER: {
            endwin();
            std::vector<std::string> sel;
            for (int i = 0; i < (int)all.size(); i++)
                if (checked[i]) sel.push_back(all[i]);
            if (sel.size() > 4) {
                std::cout << "[tm] Warning: max 4 panels. Showing first 4.\n";
                sel.resize(4);
            }
            return sel;
        }
        case 'q': case 'Q':
            endwin();
            return {};
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  명령어 셸
// ─────────────────────────────────────────────────────────────────────

void command_shell() {
    std::string cmd_line;
    while (true) {
        std::getline(std::cin, cmd_line);
        if (cmd_line.empty()) continue;

        std::stringstream ss(cmd_line);
        std::string cmd, arg;
        ss >> cmd >> arg;

        if (cmd == "exit" || cmd == "quit") {
            std::cout << "Shutting down...\n";
            exit(0);

        } else if (cmd == "list") {
            std::lock_guard<std::mutex> lk(clients_mutex);
            std::cout << "--- Connected Agents (" << connected_agents.size() << ") ---\n";
            for (const auto& a : connected_agents) std::cout << " - " << a << "\n";
            std::cout << "------------------------------\n";

        } else if (cmd == "trace") {
            if (arg.empty()) std::cout << "Usage: trace <IP>\n";
            else { target_ip_filter = arg; std::cout << "[FILTER] Tracing: " << arg << "\n"; }

        } else if (cmd == "all" || cmd == "reset") {
            target_ip_filter = "";
            std::cout << "\U0001f30d [FILTER CLEARED] Showing all agents.\n";

        } else if (cmd == "tm") {
            auto selected = select_agents_tui();
            if (!selected.empty()) {
                dashboard_active = true;
                run_dashboard(selected);
                dashboard_active = false;
                std::cout << "[tm] Dashboard closed.\n";
            }

        } else if (cmd == "help") {
            std::cout
                << "  list        : Show connected agents\n"
                << "  tm          : Trace Monitor dashboard (TUI)\n"
                << "  trace <IP>  : Filter logs by agent IP\n"
                << "  all         : Show all agent logs\n"
                << "  exit        : Stop server\n";

        } else {
            std::cout << "Unknown command. Type 'help'.\n";
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  에이전트 핸들러 (스레드별)
// ─────────────────────────────────────────────────────────────────────

void handle_client(int client_socket, struct sockaddr_in client_addr, SSL_CTX *ssl_ctx) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string ip(client_ip);

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    update_agent_status(ip, true);

    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (n <= 0) { update_agent_status(ip, false); break; }

        std::string raw(buffer);
        size_t p1 = raw.find('|');
        size_t p2 = (p1 != std::string::npos) ? raw.find('|', p1 + 1) : std::string::npos;

        if (p2 != std::string::npos) {
            std::string content = raw.substr(p2 + 1);
            if (!content.empty() && content.back() == '\n') content.pop_back();
            log_message(ip, content);
        } else {
            log_message(ip, raw);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
}

// ─────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────

int main() {
    SSL_CTX *ssl_ctx = create_server_ssl_ctx(MASTER_CERT, MASTER_KEY);
    if (!ssl_ctx) {
        std::cerr << "TLS init failed. Check " << MASTER_CERT << " & " << MASTER_KEY << "\n";
        std::cerr << "Hint: Run setup.sh to generate certificates.\n";
        return 1;
    }

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) { perror("socket"); return 1; }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 10) < 0) { perror("listen"); return 1; }

    std::cout << "========================================\n"
              << "  Renux Master Server (TLS) on Port " << PORT << "\n"
              << "  Cert: " << MASTER_CERT << "\n"
              << "  Type 'help' for commands.\n"
              << "========================================\n";

    std::thread(command_shell).detach();

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_socket < 0) { perror("accept"); continue; }
        std::thread(handle_client, new_socket, client_addr, ssl_ctx).detach();
    }

    SSL_CTX_free(ssl_ctx);
    return 0;
}
