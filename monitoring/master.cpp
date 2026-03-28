/**
 * Renux Master Server - V2.3
 * - Split TUI: 상단 로그 창 + 하단 명령어 입력
 * - tm: Trace Monitor 대시보드 (per-agent 패널, ALERT 하이라이트)
 * - trace-log <IP>: 저장된 로그 파일에서 특정 에이전트 로그 조회
 * - central_renux.log: 모든 이벤트 영구 저장
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

#define PORT          9000
#define BUFFER_SIZE   4096
#define MAX_LOG_LINES 200

#define MASTER_CERT "/etc/renux/master.crt"
#define MASTER_KEY  "/etc/renux/master.key"

/* ncurses 색상 쌍 */
#define CP_BORDER_NORMAL  1
#define CP_BORDER_ALERT   2
#define CP_TITLE_NORMAL   3
#define CP_TITLE_ALERT    4
#define CP_LINE_ALERT     5
#define CP_STATUSBAR      6
#define CP_SELECTED       7
#define CP_SYSTEM         8

// ─────────────────────────────────────────────────────────────────────
//  에이전트 데이터
// ─────────────────────────────────────────────────────────────────────

struct AgentData {
    std::deque<std::string> logs;
    bool alert = false;
};

std::mutex log_mutex;
std::mutex clients_mutex;
std::mutex agent_data_mutex;
const std::string MASTER_LOG_FILE = "central_renux.log";

std::set<std::string>            connected_agents;
std::map<std::string, AgentData> agent_data;

// ─────────────────────────────────────────────────────────────────────
//  Split TUI 전역
// ─────────────────────────────────────────────────────────────────────

static WINDOW *g_log_win  = nullptr;
static WINDOW *g_cmd_win  = nullptr;
static std::mutex g_ui_mtx;
static bool g_ui_ready    = false;
static bool g_tm_active   = false;   /* TM 모드 중: 로그 창 업데이트 억제 */

static void init_color_pairs() {
    init_pair(CP_BORDER_NORMAL, COLOR_WHITE,  -1);
    init_pair(CP_BORDER_ALERT,  COLOR_RED,    -1);
    init_pair(CP_TITLE_NORMAL,  COLOR_CYAN,   -1);
    init_pair(CP_TITLE_ALERT,   COLOR_RED,    -1);
    init_pair(CP_LINE_ALERT,    COLOR_YELLOW, -1);
    init_pair(CP_STATUSBAR,     COLOR_BLACK,  COLOR_WHITE);
    init_pair(CP_SELECTED,      COLOR_GREEN,  -1);
    init_pair(CP_SYSTEM,        COLOR_CYAN,   -1);
}

static void draw_main_chrome() {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    /* 헤더 */
    attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    char hbuf[256];
    snprintf(hbuf, sizeof(hbuf),
             " Renux Master  Port:%d  Log:%s  type 'help'",
             PORT, MASTER_LOG_FILE.c_str());
    mvprintw(0, 0, "%.*s", cols - 1, hbuf);
    attroff(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);

    /* 구분선 */
    attron(COLOR_PAIR(CP_BORDER_NORMAL));
    mvhline(rows - 2, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_BORDER_NORMAL));

    refresh();
}

static void rebuild_main_windows() {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    /* layout: row0=header, 1..rows-3=log, rows-2=separator, rows-1=cmd */
    int log_h = rows - 3;
    if (log_h < 1) log_h = 1;

    if (g_log_win) { delwin(g_log_win); g_log_win = nullptr; }
    if (g_cmd_win) { delwin(g_cmd_win); g_cmd_win = nullptr; }

    g_log_win = newwin(log_h, cols, 1, 0);
    scrollok(g_log_win, TRUE);
    idlok(g_log_win, TRUE);

    g_cmd_win = newwin(1, cols, rows - 1, 0);
}

static void init_ui() {
    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    init_color_pairs();
    rebuild_main_windows();
    draw_main_chrome();
    wrefresh(g_log_win);
    mvwprintw(g_cmd_win, 0, 0, "> ");
    wrefresh(g_cmd_win);
    g_ui_ready = true;
}

static void restore_ui() {
    /* TM 모드 종료 후 split UI 복원 */
    timeout(-1);
    noecho();
    curs_set(1);
    keypad(stdscr, TRUE);

    clear();
    refresh();
    rebuild_main_windows();
    draw_main_chrome();
    wrefresh(g_log_win);
    mvwprintw(g_cmd_win, 0, 0, "> ");
    wrefresh(g_cmd_win);
}

/* 로그 창에 한 줄 출력 (스레드 안전) */
static void ui_log(const std::string& line, int color_pair = 0, bool bold = false) {
    if (!g_ui_ready || g_tm_active) return;
    std::lock_guard<std::mutex> lk(g_ui_mtx);

    if (color_pair) wattron(g_log_win, COLOR_PAIR(color_pair) | (bold ? A_BOLD : 0));
    wprintw(g_log_win, "%s\n", line.c_str());
    if (color_pair) wattroff(g_log_win, COLOR_PAIR(color_pair) | A_BOLD);

    wnoutrefresh(g_log_win);
    wnoutrefresh(g_cmd_win);
    doupdate();
}

// ─────────────────────────────────────────────────────────────────────
//  로그 기록 & 에이전트 상태
// ─────────────────────────────────────────────────────────────────────

void log_message(const std::string& ip, const std::string& msg) {
    /* 파일 영구 저장 */
    {
        std::lock_guard<std::mutex> lk(log_mutex);
        std::ofstream f(MASTER_LOG_FILE, std::ios::app);
        if (f.is_open()) {
            std::time_t now = std::time(nullptr);
            char tbuf[32];
            std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
            f << "[" << tbuf << "] [Agent: " << ip << "] " << msg << "\n";
        }
    }

    /* per-agent 인메모리 버퍼 */
    {
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        auto& d = agent_data[ip];
        d.logs.push_back(msg);
        if (d.logs.size() > MAX_LOG_LINES) d.logs.pop_front();
        if (msg.find("ALERT:") != std::string::npos) d.alert = true;
    }

    /* 로그 창 출력 */
    bool is_alert = (msg.find("ALERT:") != std::string::npos);
    std::string line = "[" + ip + "] " + msg;
    if (is_alert)
        ui_log(line, CP_LINE_ALERT, true);
    else
        ui_log(line);
}

void update_agent_status(const std::string& ip, bool connected) {
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        if (connected) connected_agents.insert(ip);
        else           connected_agents.erase(ip);
    }
    {
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        if (connected) agent_data[ip];
    }

    std::string msg = connected
        ? "[SYSTEM] Agent connected: " + ip
        : "[SYSTEM] Agent disconnected: " + ip;
    ui_log(msg, CP_SYSTEM, true);
}

// ─────────────────────────────────────────────────────────────────────
//  TUI Dashboard (tm)
// ─────────────────────────────────────────────────────────────────────

struct PanelLayout { int y, x, h, w; };

static std::vector<PanelLayout> calc_layout(int n, int rows, int cols) {
    int usable = rows - 1;
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
    } else {
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

    wattron(win, COLOR_PAIR(alert ? CP_BORDER_ALERT : CP_BORDER_NORMAL) | (alert ? A_BOLD : 0));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(CP_BORDER_ALERT) | COLOR_PAIR(CP_BORDER_NORMAL) | A_BOLD);

    std::string title = alert ? (" !! " + ip + " !! ") : (" " + ip + " ");
    int tx = std::max(1, (w - (int)title.size()) / 2);
    wattron(win, COLOR_PAIR(alert ? CP_TITLE_ALERT : CP_TITLE_NORMAL) | A_BOLD);
    mvwprintw(win, 0, tx, "%s", title.c_str());
    wattroff(win, COLOR_PAIR(CP_TITLE_ALERT) | COLOR_PAIR(CP_TITLE_NORMAL) | A_BOLD);

    int ch = h - 2, cw = w - 2;
    int start = (int)logs.size() > ch ? (int)logs.size() - ch : 0;

    for (int i = 0; i < ch && start + i < (int)logs.size(); i++) {
        std::string line = logs[start + i];
        if ((int)line.size() > cw) line = line.substr(0, cw);
        bool is_alert = (line.find("ALERT:") != std::string::npos);
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

    std::string left  = std::string(" ") + tbuf + "  Agents: " + std::to_string(n_agents);
    std::string right = "Alerts: " + std::to_string(n_alerts) + "  [c]lear  [q]uit ";

    int pad = cols - (int)left.size() - (int)right.size();
    std::string bar = left + std::string(std::max(0, pad), ' ') + right;
    if ((int)bar.size() > cols) bar = bar.substr(0, cols);

    attron(COLOR_PAIR(CP_STATUSBAR) | A_REVERSE);
    mvprintw(rows - 1, 0, "%s", bar.c_str());
    attroff(COLOR_PAIR(CP_STATUSBAR) | A_REVERSE);
    refresh();
}

static void run_dashboard(const std::vector<std::string>& ips) {
    init_color_pairs();
    curs_set(0);
    timeout(500);

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
    curs_set(1);
    timeout(-1);
}

// ─────────────────────────────────────────────────────────────────────
//  에이전트 선택 화면 (full-screen, initscr 없이)
// ─────────────────────────────────────────────────────────────────────

static std::vector<std::string> select_agents_tui() {
    std::vector<std::string> all;
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        all.assign(connected_agents.begin(), connected_agents.end());
    }
    if (all.empty()) {
        ui_log("[tm] No connected agents.", CP_SYSTEM, true);
        return {};
    }

    init_color_pairs();
    curs_set(0);
    noecho();

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
            std::vector<std::string> sel;
            for (int i = 0; i < (int)all.size(); i++)
                if (checked[i]) sel.push_back(all[i]);
            if (sel.size() > 4) sel.resize(4);
            return sel;
        }
        case 'q': case 'Q':
            return {};
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  명령어 셸
// ─────────────────────────────────────────────────────────────────────

void command_shell() {
    char buf[512];
    while (true) {
        /* 프롬프트 */
        {
            std::lock_guard<std::mutex> lk(g_ui_mtx);
            mvwprintw(g_cmd_win, 0, 0, "> ");
            wclrtoeol(g_cmd_win);
            wrefresh(g_cmd_win);
        }

        echo();
        memset(buf, 0, sizeof(buf));
        mvwgetnstr(g_cmd_win, 0, 2, buf, sizeof(buf) - 1);
        noecho();

        std::string cmd_line(buf);
        if (cmd_line.empty()) continue;

        std::stringstream ss(cmd_line);
        std::string cmd, arg;
        ss >> cmd >> arg;

        if (cmd == "exit" || cmd == "quit") {
            endwin();
            exit(0);

        } else if (cmd == "list") {
            std::lock_guard<std::mutex> lk(clients_mutex);
            ui_log("--- Connected Agents (" +
                   std::to_string(connected_agents.size()) + ") ---", CP_TITLE_NORMAL, true);
            for (const auto& a : connected_agents)
                ui_log("  - " + a);
            ui_log("------------------------------");

        } else if (cmd == "tm") {
            g_tm_active = true;
            clear(); refresh();

            auto selected = select_agents_tui();
            if (!selected.empty()) {
                clear(); refresh();
                run_dashboard(selected);
            }

            g_tm_active = false;
            restore_ui();

        } else if (cmd == "trace-log") {
            if (arg.empty()) {
                ui_log("Usage: trace-log <IP>", CP_SYSTEM, true);
            } else {
                std::ifstream f(MASTER_LOG_FILE);
                if (!f.is_open()) {
                    ui_log("[ERROR] Cannot open " + MASTER_LOG_FILE, CP_BORDER_ALERT, true);
                } else {
                    std::string needle = "[Agent: " + arg + "]";
                    std::string line;
                    int cnt = 0;
                    ui_log("--- trace-log: " + arg + " ---", CP_TITLE_NORMAL, true);
                    while (std::getline(f, line)) {
                        if (line.find(needle) != std::string::npos) {
                            bool is_alert = (line.find("ALERT:") != std::string::npos);
                            ui_log(line, is_alert ? CP_LINE_ALERT : 0, is_alert);
                            cnt++;
                        }
                    }
                    ui_log("--- " + std::to_string(cnt) + " entries ---", CP_TITLE_NORMAL, true);
                }
            }

        } else if (cmd == "help") {
            ui_log("  list              : 연결된 에이전트 목록", CP_SYSTEM, false);
            ui_log("  tm                : Trace Monitor 대시보드 (TUI)", CP_SYSTEM, false);
            ui_log("  trace-log <IP>    : 저장된 로그에서 에이전트 기록 조회", CP_SYSTEM, false);
            ui_log("  exit              : 서버 종료", CP_SYSTEM, false);

        } else {
            ui_log("Unknown command. Type 'help'.", CP_BORDER_ALERT, false);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  에이전트 핸들러 (스레드별)
// ─────────────────────────────────────────────────────────────────────

void handle_client(int client_socket, struct sockaddr_in client_addr, SSL_CTX *ssl_ctx) {
    char sock_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), sock_ip, INET_ADDRSTRLEN);

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    /* 에이전트 식별 IP: HELLO 메시지에서 추출 (NAT/mock 대응) */
    std::string ip(sock_ip);
    bool registered = false;

    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (n <= 0) { if (registered) update_agent_status(ip, false); break; }

        std::string raw(buffer);
        size_t p1 = raw.find('|');
        size_t p2 = (p1 != std::string::npos) ? raw.find('|', p1 + 1) : std::string::npos;

        if (p2 == std::string::npos) { log_message(ip, raw); continue; }

        std::string type    = raw.substr(0, p1);
        std::string msg_ip  = raw.substr(p1 + 1, p2 - p1 - 1);
        std::string content = raw.substr(p2 + 1);
        if (!content.empty() && content.back() == '\n') content.pop_back();

        if (!registered) {
            ip = msg_ip;
            update_agent_status(ip, true);
            registered = true;
        }

        if (type != "HELLO") log_message(ip, content);
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
        std::cerr << "Hint: Run install.sh (master) to generate certificates.\n";
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

    init_ui();
    ui_log("Renux Master started. Listening on port " + std::to_string(PORT), CP_SYSTEM, true);

    std::thread(command_shell).detach();

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_socket < 0) continue;
        std::thread(handle_client, new_socket, client_addr, ssl_ctx).detach();
    }

    endwin();
    SSL_CTX_free(ssl_ctx);
    return 0;
}
