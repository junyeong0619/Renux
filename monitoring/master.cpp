/**
 * Renux Master Server - V2.4
 * - Split TUI: 상단 로그 창 + 하단 명령 입력 (단일 스레드 ncurses)
 * - 에이전트 태깅: tag/untag/tags, tags.conf 영구 저장
 * - tm: Trace Monitor 대시보드 (per-agent 패널, ALERT 하이라이트)
 * - trace-log <ip|tag>: 오버레이 창에서 에이전트 로그 조회
 * - trace-tr  <H:H>   : 시간대 ALERT 필터 (e.g. trace-tr 1:13)
 */

#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <deque>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <algorithm>
#include <set>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ncurses.h>
#include <clocale>
#include "../utils/ssl_utils.h"

#define PORT           9000
#define BUFFER_SIZE    4096
#define MAX_LOG_LINES  200

#define MASTER_CERT "/etc/renux/master.crt"
#define MASTER_KEY  "/etc/renux/master.key"

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

std::mutex agent_data_mutex;
std::mutex clients_mutex;
std::mutex log_file_mutex;

const std::string MASTER_LOG_FILE = "central_renux.log";
const std::string TAG_FILE        = "renux_tags.conf";

std::set<std::string>            connected_agents;
std::map<std::string, AgentData> agent_data;

// ─────────────────────────────────────────────────────────────────────
//  태그 시스템
// ─────────────────────────────────────────────────────────────────────

std::mutex tag_mutex;
std::map<std::string, std::string> g_tag_to_ip;   /* name → ip  */
std::map<std::string, std::string> g_ip_to_tag;   /* ip   → name */

void save_tags() {
    std::lock_guard<std::mutex> lk(tag_mutex);
    std::ofstream f(TAG_FILE);
    for (auto& [name, ip] : g_tag_to_ip)
        f << name << "=" << ip << "\n";
}

void load_tags() {
    std::ifstream f(TAG_FILE);
    if (!f.is_open()) return;
    std::string line;
    std::lock_guard<std::mutex> lk(tag_mutex);
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string name = line.substr(0, eq);
        std::string ip   = line.substr(eq + 1);
        g_tag_to_ip[name] = ip;
        g_ip_to_tag[ip]   = name;
    }
}

/* 태그 또는 IP 문자열을 IP로 변환 */
std::string resolve_ip(const std::string& s) {
    std::lock_guard<std::mutex> lk(tag_mutex);
    auto it = g_tag_to_ip.find(s);
    return (it != g_tag_to_ip.end()) ? it->second : s;
}

/* IP를 "tag | ip" 또는 "ip" 형태로 표시 */
std::string display_name(const std::string& ip) {
    std::lock_guard<std::mutex> lk(tag_mutex);
    auto it = g_ip_to_tag.find(ip);
    return (it != g_ip_to_tag.end()) ? (it->second + " | " + ip) : ip;
}

// ─────────────────────────────────────────────────────────────────────
//  UI 메시지 큐 (백그라운드 스레드 → UI 스레드)
//  ncurses는 command_shell 스레드에서만 호출한다.
// ─────────────────────────────────────────────────────────────────────

struct LogEntry {
    std::string text;
    int  color_pair;
    bool bold;
};

std::queue<LogEntry> g_ui_queue;
std::mutex           g_ui_queue_mtx;

/* 어느 스레드에서나 호출 가능 (ncurses 호출 없음) */
static void ui_enqueue(const std::string& text, int cp = 0, bool bold = false) {
    std::lock_guard<std::mutex> lk(g_ui_queue_mtx);
    g_ui_queue.push({text, cp, bold});
}

// ─────────────────────────────────────────────────────────────────────
//  Split TUI
// ─────────────────────────────────────────────────────────────────────

static WINDOW *g_log_win  = nullptr;
static WINDOW *g_cmd_win  = nullptr;
static bool    g_ui_ready = false;

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
    attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    char hbuf[256];
    snprintf(hbuf, sizeof(hbuf),
             " Renux Master  Port:%d  Log:%s  'help'", PORT, MASTER_LOG_FILE.c_str());
    mvprintw(0, 0, "%.*s", cols - 1, hbuf);
    attroff(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
    attron(COLOR_PAIR(CP_BORDER_NORMAL));
    mvhline(rows - 2, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_BORDER_NORMAL));
    refresh();
}

static void rebuild_main_windows() {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
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
    setlocale(LC_ALL, "");
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
    wrefresh(g_cmd_win);
    g_ui_ready = true;
}

static void restore_ui() {
    timeout(-1);
    noecho();
    curs_set(1);
    keypad(stdscr, TRUE);
    clear(); refresh();
    rebuild_main_windows();
    draw_main_chrome();
    wrefresh(g_log_win);
    wrefresh(g_cmd_win);
}

/* UI 큐 드레인 (UI 스레드 전용) */
static void ui_flush() {
    if (!g_ui_ready || !g_log_win) return;
    std::lock_guard<std::mutex> lk(g_ui_queue_mtx);
    while (!g_ui_queue.empty()) {
        auto& e = g_ui_queue.front();
        if (e.color_pair)
            wattron(g_log_win, COLOR_PAIR(e.color_pair) | (e.bold ? A_BOLD : 0));
        wprintw(g_log_win, "%s\n", e.text.c_str());
        if (e.color_pair)
            wattroff(g_log_win, COLOR_PAIR(e.color_pair) | A_BOLD);
        g_ui_queue.pop();
    }
    wnoutrefresh(g_log_win);
}

// ─────────────────────────────────────────────────────────────────────
//  오버레이 창 (스크롤 가능, q로 닫기)
// ─────────────────────────────────────────────────────────────────────

static void show_overlay(const std::string& title, const std::vector<std::string>& lines) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    WINDOW *win = newwin(rows, cols, 0, 0);
    keypad(win, TRUE);
    timeout(-1);

    int view_h = rows - 2;
    int scroll  = 0;
    int total   = (int)lines.size();

    while (true) {
        werase(win);

        /* 헤더 */
        wattron(win, COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvwhline(win, 0, 0, ' ', cols);
        mvwprintw(win, 0, 1, " %s", title.c_str());
        wattroff(win, COLOR_PAIR(CP_STATUSBAR) | A_BOLD);

        /* 내용 */
        for (int i = 0; i < view_h - 1 && scroll + i < total; i++) {
            const std::string& line = lines[scroll + i];
            bool is_alert = (line.find("ALERT:") != std::string::npos);
            if (is_alert) wattron(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
            int cw = cols - 2;
            std::string disp = line.size() > (size_t)cw ? line.substr(0, cw) : line;
            mvwprintw(win, i + 1, 1, "%-*s", cw, disp.c_str());
            if (is_alert) wattroff(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
        }

        /* 푸터 */
        wattron(win, COLOR_PAIR(CP_STATUSBAR));
        mvwhline(win, rows - 1, 0, ' ', cols);
        mvwprintw(win, rows - 1, 1,
                  " %d/%d lines  UP/DOWN: scroll  PgUp/PgDn | Ctrl+B/F: page  q: close",
                  std::min(scroll + view_h - 1, total), total);
        wattroff(win, COLOR_PAIR(CP_STATUSBAR));

        wrefresh(win);

        int ch = wgetch(win);
        if (ch == 'q' || ch == 'Q') break;
        if (ch == KEY_UP   && scroll > 0) scroll--;
        if (ch == KEY_DOWN && scroll + view_h - 1 < total) scroll++;
        if (ch == KEY_PPAGE || ch == 2)  scroll = std::max(0, scroll - (view_h - 1));           /* PgUp / Ctrl+B */
        if (ch == KEY_NPAGE || ch == 6)  scroll = std::min(std::max(0, total - view_h + 1), scroll + view_h - 1); /* PgDn / Ctrl+F */
        if (ch == KEY_HOME) scroll = 0;
        if (ch == KEY_END)  scroll = std::max(0, total - view_h + 1);
        if (ch == KEY_RESIZE) {
            getmaxyx(stdscr, rows, cols);
            wresize(win, rows, cols);
            view_h = rows - 2;
        }
    }

    delwin(win);
    restore_ui();
    keypad(g_cmd_win, TRUE);
    wtimeout(g_cmd_win, 100);
}

// ─────────────────────────────────────────────────────────────────────
//  로그 기록
// ─────────────────────────────────────────────────────────────────────

void log_message(const std::string& ip, const std::string& msg) {
    /* 파일 저장 */
    {
        std::lock_guard<std::mutex> lk(log_file_mutex);
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

    /* UI 큐 */
    bool is_alert = (msg.find("ALERT:") != std::string::npos);
    std::string line = "[" + display_name(ip) + "] " + msg;
    if (is_alert)
        ui_enqueue(line, CP_LINE_ALERT, true);
    else
        ui_enqueue(line);
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
        ? "[SYSTEM] Agent connected: " + display_name(ip)
        : "[SYSTEM] Agent disconnected: " + display_name(ip);
    ui_enqueue(msg, CP_SYSTEM, true);
}

// ─────────────────────────────────────────────────────────────────────
//  인터랙티브 태그 UI (UI 스레드 전용)
// ─────────────────────────────────────────────────────────────────────

/* 화면의 특정 위치에서 문자열을 한 글자씩 입력받는다 (ESC로 취소) */
static std::string read_string_at(int y, int x, int maxlen) {
    char buf[256] = {};
    int  pos = 0;
    curs_set(1);
    timeout(-1);

    while (true) {
        mvprintw(y, x, "> %-*s", maxlen, buf);
        move(y, x + 2 + pos);
        refresh();

        int ch = getch();
        if (ch == '\n' || ch == KEY_ENTER) break;
        if (ch == 27)  { buf[0] = '\0'; break; }   /* ESC: 취소 */
        if ((ch == KEY_BACKSPACE || ch == 127) && pos > 0) buf[--pos] = '\0';
        else if (ch >= 32 && ch < 127 && pos < maxlen - 1) buf[pos++] = (char)ch;
    }
    curs_set(0);
    return std::string(buf);
}

static void cmd_tag_interactive() {
    std::vector<std::string> agents;
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        agents.assign(connected_agents.begin(), connected_agents.end());
    }
    if (agents.empty()) {
        ui_enqueue("No connected agents.", CP_SYSTEM, true);
        return;
    }

    curs_set(0);
    int cursor = 0;
    std::string selected_ip;

    /* ── 에이전트 선택 ── */
    while (true) {
        clear();
        attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 2, " Tag Agent - Select agent to tag");
        attroff(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvprintw(1, 2, "UP/DOWN: move  ENTER: select  q: cancel");

        for (int i = 0; i < (int)agents.size(); i++) {
            std::string cur_tag;
            {
                std::lock_guard<std::mutex> lk(tag_mutex);
                auto it = g_ip_to_tag.find(agents[i]);
                if (it != g_ip_to_tag.end()) cur_tag = "  [" + it->second + "]";
            }
            if (i == cursor) attron(A_REVERSE);
            attron(COLOR_PAIR(CP_TITLE_NORMAL));
            mvprintw(i + 3, 4, "%-18s", agents[i].c_str());
            attroff(COLOR_PAIR(CP_TITLE_NORMAL));
            printw("%s", cur_tag.c_str());
            if (i == cursor) attroff(A_REVERSE);
        }
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') goto done;
        if (ch == KEY_UP)   cursor = std::max(0, cursor - 1);
        if (ch == KEY_DOWN) cursor = std::min((int)agents.size() - 1, cursor + 1);
        if (ch == '\n' || ch == KEY_ENTER) { selected_ip = agents[cursor]; break; }
    }

    /* ── 이름 입력 ── */
    {
        clear();
        attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 2, " Tag Agent - Enter name for %s", selected_ip.c_str());
        attroff(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvprintw(2, 4, "Tag name (ESC to cancel):");
        refresh();

        std::string name = read_string_at(3, 4, 32);
        if (!name.empty()) {
            {
                std::lock_guard<std::mutex> lk(tag_mutex);
                auto old = g_ip_to_tag.find(selected_ip);
                if (old != g_ip_to_tag.end()) g_tag_to_ip.erase(old->second);
                g_tag_to_ip[name]       = selected_ip;
                g_ip_to_tag[selected_ip] = name;
            }
            save_tags();
            ui_enqueue("Tagged: " + selected_ip + " -> " + name, CP_SYSTEM, true);
        }
    }

done:
    restore_ui();
    keypad(g_cmd_win, TRUE);
    wtimeout(g_cmd_win, 100);
}

static void cmd_untag_interactive() {
    std::vector<std::pair<std::string, std::string>> tagged;   /* name, ip */
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        for (auto& [name, ip] : g_tag_to_ip)
            tagged.push_back({name, ip});
    }
    if (tagged.empty()) {
        ui_enqueue("No tags defined.", CP_SYSTEM, true);
        return;
    }

    curs_set(0);
    int cursor = 0;

    while (true) {
        clear();
        attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 2, " Untag Agent - Select tag to remove");
        attroff(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvprintw(1, 2, "UP/DOWN: move  ENTER: remove  q: cancel");

        for (int i = 0; i < (int)tagged.size(); i++) {
            if (i == cursor) attron(A_REVERSE);
            attron(COLOR_PAIR(CP_SELECTED));
            mvprintw(i + 3, 4, "%-15s", tagged[i].first.c_str());
            attroff(COLOR_PAIR(CP_SELECTED));
            printw(" -> %s", tagged[i].second.c_str());
            if (i == cursor) attroff(A_REVERSE);
        }
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;
        if (ch == KEY_UP)   cursor = std::max(0, cursor - 1);
        if (ch == KEY_DOWN) cursor = std::min((int)tagged.size() - 1, cursor + 1);
        if (ch == '\n' || ch == KEY_ENTER) {
            std::string name = tagged[cursor].first;
            std::string ip   = tagged[cursor].second;
            {
                std::lock_guard<std::mutex> lk(tag_mutex);
                g_ip_to_tag.erase(ip);
                g_tag_to_ip.erase(name);
            }
            save_tags();
            ui_enqueue("Removed tag: " + name + " (" + ip + ")", CP_SYSTEM, true);
            break;
        }
    }

    restore_ui();
    keypad(g_cmd_win, TRUE);
    wtimeout(g_cmd_win, 100);
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

    std::string dname = display_name(ip);
    std::string title = alert ? (" !! " + dname + " !! ") : (" " + dname + " ");
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

static void draw_statusbar_tm(int rows, int cols, int n_agents, int n_alerts) {
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
        draw_statusbar_tm(rows, cols, n, n_alerts);
    }

    for (auto w : wins) delwin(w);
    curs_set(1);
    timeout(-1);
}

// ─────────────────────────────────────────────────────────────────────
//  에이전트 선택 화면
// ─────────────────────────────────────────────────────────────────────

static std::vector<std::string> select_agents_tui() {
    std::vector<std::string> all;
    {
        std::lock_guard<std::mutex> lk(clients_mutex);
        all.assign(connected_agents.begin(), connected_agents.end());
    }
    if (all.empty()) {
        ui_enqueue("[tm] No connected agents.", CP_SYSTEM, true);
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
        mvprintw(0, 2, "Trace Monitor - Select agents (max 4)");
        attroff(COLOR_PAIR(CP_TITLE_NORMAL) | A_BOLD);
        mvprintw(1, 2, "UP/DOWN: move  SPACE: toggle  a: all  ENTER: confirm  q: cancel");

        for (int i = 0; i < (int)all.size(); i++) {
            if (i == cursor) attron(A_REVERSE);
            if (checked[i]) {
                attron(COLOR_PAIR(CP_SELECTED));
                mvprintw(i + 3, 4, "[x] %s", display_name(all[i]).c_str());
                attroff(COLOR_PAIR(CP_SELECTED));
            } else {
                mvprintw(i + 3, 4, "[ ] %s", display_name(all[i]).c_str());
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
            std::fill(checked.begin(), checked.end(), true); break;
        case '\n': case KEY_ENTER: {
            std::vector<std::string> sel;
            for (int i = 0; i < (int)all.size(); i++)
                if (checked[i]) sel.push_back(all[i]);
            if (sel.size() > 4) sel.resize(4);
            return sel;
        }
        case 'q': case 'Q': return {};
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  명령어 핸들러
// ─────────────────────────────────────────────────────────────────────

static void cmd_trace_log(const std::string& target) {
    std::string ip = resolve_ip(target);
    std::ifstream f(MASTER_LOG_FILE);
    if (!f.is_open()) {
        ui_enqueue("[ERROR] Cannot open " + MASTER_LOG_FILE, CP_BORDER_ALERT, true);
        return;
    }
    std::string needle = "[Agent: " + ip + "]";
    std::vector<std::string> results;
    std::string line;
    while (std::getline(f, line))
        if (line.find(needle) != std::string::npos) results.push_back(line);

    show_overlay("trace-log: " + target + " (" + ip + ")  [" +
                 std::to_string(results.size()) + " entries]", results);
}

static void cmd_trace_tr(const std::string& range) {
    int start_h = -1, end_h = -1;
    if (sscanf(range.c_str(), "%d:%d", &start_h, &end_h) != 2 ||
        start_h < 0 || start_h > 23 || end_h < 0 || end_h > 23) {
        ui_enqueue("Usage: trace-tr <start>:<end>  (e.g. trace-tr 1:13)", CP_SYSTEM, true);
        return;
    }

    std::ifstream f(MASTER_LOG_FILE);
    if (!f.is_open()) {
        ui_enqueue("[ERROR] Cannot open " + MASTER_LOG_FILE, CP_BORDER_ALERT, true);
        return;
    }

    /* 로그 형식: [YYYY-MM-DD HH:MM:SS] [Agent: ip] msg */
    std::vector<std::string> results;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("ALERT:") == std::string::npos) continue;
        if (line.size() < 14 || line[0] != '[') continue;
        int hour = -1;
        sscanf(line.c_str() + 12, "%d", &hour);
        if (hour < 0) continue;

        bool in_range = (start_h <= end_h)
            ? (hour >= start_h && hour <= end_h)
            : (hour >= start_h || hour <= end_h);  /* 자정 걸치는 경우 */
        if (in_range) results.push_back(line);
    }

    char title[128];
    snprintf(title, sizeof(title),
             "trace-tr %02d:00 ~ %02d:00  [%d ALERTs]",
             start_h, end_h, (int)results.size());
    show_overlay(title, results);
}

static void cmd_tag(const std::string& ip, const std::string& name) {
    if (ip.empty() || name.empty()) {
        ui_enqueue("Usage: tag <ip> <name>", CP_SYSTEM, true); return;
    }
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        /* 기존 태그 제거 */
        auto old = g_ip_to_tag.find(ip);
        if (old != g_ip_to_tag.end()) g_tag_to_ip.erase(old->second);
        g_tag_to_ip[name] = ip;
        g_ip_to_tag[ip]   = name;
    }
    save_tags();
    ui_enqueue("Tagged: " + ip + " -> " + name, CP_SYSTEM, true);
}

static void cmd_untag(const std::string& name) {
    if (name.empty()) {
        ui_enqueue("Usage: untag <name>", CP_SYSTEM, true); return;
    }
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        auto it = g_tag_to_ip.find(name);
        if (it == g_tag_to_ip.end()) {
            ui_enqueue("Tag not found: " + name, CP_BORDER_ALERT, true); return;
        }
        g_ip_to_tag.erase(it->second);
        g_tag_to_ip.erase(it);
    }
    save_tags();
    ui_enqueue("Removed tag: " + name, CP_SYSTEM, true);
}

static void cmd_tags() {
    std::lock_guard<std::mutex> lk(tag_mutex);
    if (g_tag_to_ip.empty()) {
        ui_enqueue("No tags defined. Use: tag <ip> <name>", CP_SYSTEM, false);
        return;
    }
    ui_enqueue("--- Tags ---", CP_TITLE_NORMAL, true);
    for (auto& [name, ip] : g_tag_to_ip)
        ui_enqueue("  " + name + " -> " + ip);
    ui_enqueue("------------");
}

// ─────────────────────────────────────────────────────────────────────
//  명령어 셸 (UI 스레드 — 모든 ncurses 호출은 여기서만)
// ─────────────────────────────────────────────────────────────────────

void command_shell() {
    char input_buf[512] = {};
    int  input_pos = 0;

    keypad(g_cmd_win, TRUE);
    wtimeout(g_cmd_win, 100);

    while (true) {
        /* 큐 드레인 */
        ui_flush();

        /* 프롬프트 갱신 */
        mvwprintw(g_cmd_win, 0, 0, "> %-*s", COLS - 3, input_buf);
        wmove(g_cmd_win, 0, 2 + input_pos);
        wnoutrefresh(g_cmd_win);
        doupdate();

        int ch = wgetch(g_cmd_win);
        if (ch == ERR) continue;

        if (ch == '\n' || ch == KEY_ENTER) {
            std::string cmd_line(input_buf);
            memset(input_buf, 0, sizeof(input_buf));
            input_pos = 0;
            if (cmd_line.empty()) continue;

            std::stringstream ss(cmd_line);
            std::string cmd, arg1, arg2;
            ss >> cmd >> arg1 >> arg2;

            if (cmd == "exit" || cmd == "quit") {
                endwin(); exit(0);

            } else if (cmd == "list") {
                std::lock_guard<std::mutex> lk(clients_mutex);
                ui_enqueue("--- Connected Agents (" +
                           std::to_string(connected_agents.size()) + ") ---",
                           CP_TITLE_NORMAL, true);
                for (auto& a : connected_agents)
                    ui_enqueue("  " + display_name(a));
                ui_enqueue("------------------------------");

            } else if (cmd == "tag") {
                if (arg1.empty()) cmd_tag_interactive();
                else              cmd_tag(arg1, arg2);

            } else if (cmd == "untag") {
                if (arg1.empty()) cmd_untag_interactive();
                else              cmd_untag(arg1);

            } else if (cmd == "tags") {
                cmd_tags();

            } else if (cmd == "tm") {
                clear(); refresh();
                auto selected = select_agents_tui();
                if (!selected.empty()) {
                    clear(); refresh();
                    run_dashboard(selected);
                }
                restore_ui();
                keypad(g_cmd_win, TRUE);
                wtimeout(g_cmd_win, 100);

            } else if (cmd == "trace-log") {
                if (arg1.empty())
                    ui_enqueue("Usage: trace-log <ip|tag>", CP_SYSTEM, true);
                else
                    cmd_trace_log(arg1);

            } else if (cmd == "trace-tr") {
                if (arg1.empty())
                    ui_enqueue("Usage: trace-tr <start>:<end>  e.g. trace-tr 1:13", CP_SYSTEM, true);
                else
                    cmd_trace_tr(arg1);

            } else if (cmd == "help") {
                ui_enqueue("  list                 : 연결된 에이전트 목록", CP_SYSTEM, false);
                ui_enqueue("  tag [<ip> <name>]    : 태그 지정 (인수 없으면 선택 UI)", CP_SYSTEM, false);
                ui_enqueue("  untag [<name>]       : 태그 제거 (인수 없으면 선택 UI)", CP_SYSTEM, false);
                ui_enqueue("  tags                 : 태그 목록", CP_SYSTEM, false);
                ui_enqueue("  tm                   : Trace Monitor 대시보드", CP_SYSTEM, false);
                ui_enqueue("  trace-log <ip|tag>   : 에이전트 전체 로그 조회", CP_SYSTEM, false);
                ui_enqueue("  trace-tr  <H:H>      : 시간대 ALERT 조회 (e.g. 1:13)", CP_SYSTEM, false);
                ui_enqueue("  exit                 : 서버 종료", CP_SYSTEM, false);

            } else {
                ui_enqueue("Unknown command. Type 'help'.", CP_BORDER_ALERT, false);
            }

        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
            if (input_pos > 0) input_buf[--input_pos] = '\0';
        } else if (ch >= 32 && ch < 127 && input_pos < 500) {
            input_buf[input_pos++] = (char)ch;
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
        SSL_free(ssl); close(client_socket); return;
    }

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
        fprintf(stderr, "TLS init failed. Check %s & %s\n", MASTER_CERT, MASTER_KEY);
        fprintf(stderr, "Hint: Run install.sh (master) to generate certificates.\n");
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

    load_tags();
    init_ui();
    ui_enqueue("Renux Master started on port " + std::to_string(PORT), CP_SYSTEM, true);

    /* accept 루프는 메인 스레드, command_shell이 UI 스레드 */
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
