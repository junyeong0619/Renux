/**
 * Renux Master Server - V2.6
 * 신규:
 *   - Geolocation: REVERSE_SHELL 탐지 시 원격 IP 위치 자동 조회
 *   - Risk Score : 이벤트 가중치 누적 (0-100, LOW/MEDIUM/HIGH/CRITICAL)
 *   - Alert Burst: 30초 내 3회 이상 ALERT → CRITICAL 격상
 *   - stats [ip]  : 에이전트별 이벤트 통계 + ASCII 바 차트
 *   - Heartbeat  : list에 마지막 수신 시간 표시
 *   - Per-agent log: agents/{ip}.log 에 에이전트별 로그 분리 저장
 *   - Graph mode : tm 대시보드에서 [g] 키로 로그 뷰 <-> 실시간 그래프 전환
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
#include <sys/stat.h>
#include <ncurses.h>
#include <clocale>
#include "../utils/ssl_utils.h"

#define PORT           9000
#define BUFFER_SIZE    4096
#define MAX_LOG_LINES  200
#define BURST_WINDOW   30    /* 초 */
#define BURST_THRESH   3     /* BURST_WINDOW 안에 몇 번 이상이면 CRITICAL */

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
#define CP_CRITICAL       9   /* 밝은 빨강 */
#define CP_RISK_HIGH     10
#define CP_RISK_MED      11
#define CP_RISK_LOW      12

// ─────────────────────────────────────────────────────────────────────
//  에이전트 데이터
// ─────────────────────────────────────────────────────────────────────

struct AgentData {
    std::deque<std::string>  logs;
    bool                     alert    = false;
    bool                     critical = false;   /* burst 감지 */
    int                      risk     = 0;       /* 0-100 */
    std::time_t              last_seen = 0;

    /* 이벤트 카운터 */
    int cnt_exec    = 0;
    int cnt_file    = 0;
    int cnt_reverse = 0;
    int cnt_webshell= 0;

    /* 버스트 감지용 ALERT 타임스탬프 */
    std::deque<std::time_t> alert_ts;

    /* 그래프용: 이벤트 종류별 타임스탬프 (최근 GRAPH_WINDOW_SEC 초) */
    std::deque<std::time_t> exec_times;
    std::deque<std::time_t> file_times;
    std::deque<std::time_t> reverse_times;
    std::deque<std::time_t> webshell_times;
};

std::mutex agent_data_mutex;
std::mutex clients_mutex;
std::mutex log_file_mutex;

const std::string MASTER_LOG_FILE = "central_renux.log";
const std::string TAG_FILE        = "renux_tags.conf";
const std::string AGENT_LOG_DIR   = "agents";         /* 에이전트별 로그 디렉토리 */

#define GRAPH_WINDOW_SEC  60   /* 그래프 표시 시간 범위 (초) */

std::set<std::string>            connected_agents;
std::map<std::string, AgentData> agent_data;

// ─────────────────────────────────────────────────────────────────────
//  태그 시스템
// ─────────────────────────────────────────────────────────────────────

std::mutex tag_mutex;
std::map<std::string, std::string> g_tag_to_ip;
std::map<std::string, std::string> g_ip_to_tag;

void save_tags() {
    std::lock_guard<std::mutex> lk(tag_mutex);
    std::ofstream f(TAG_FILE);
    for (auto& [name, ip] : g_tag_to_ip) f << name << "=" << ip << "\n";
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

std::string resolve_ip(const std::string& s) {
    std::lock_guard<std::mutex> lk(tag_mutex);
    auto it = g_tag_to_ip.find(s);
    return (it != g_tag_to_ip.end()) ? it->second : s;
}

std::string display_name(const std::string& ip) {
    std::lock_guard<std::mutex> lk(tag_mutex);
    auto it = g_ip_to_tag.find(ip);
    return (it != g_ip_to_tag.end()) ? (it->second + " | " + ip) : ip;
}

// ─────────────────────────────────────────────────────────────────────
//  유틸리티
// ─────────────────────────────────────────────────────────────────────

static std::string time_ago(std::time_t t) {
    if (t == 0) return "never";
    int d = (int)(std::time(nullptr) - t);
    if (d < 60)   return std::to_string(d) + "s ago";
    if (d < 3600) return std::to_string(d / 60) + "m ago";
    return std::to_string(d / 3600) + "h ago";
}

static const char* risk_label(int r) {
    if (r >= 80) return "CRITICAL";
    if (r >= 50) return "HIGH";
    if (r >= 20) return "MEDIUM";
    return "LOW";
}

static int risk_color(int r) {
    if (r >= 80) return CP_CRITICAL;
    if (r >= 50) return CP_RISK_HIGH;
    if (r >= 20) return CP_RISK_MED;
    return CP_RISK_LOW;
}

static bool is_private_ip(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return true;
    uint32_t h = ntohl(addr.s_addr);
    return (h >> 24 == 10) ||
           (h >> 24 == 127) ||
           ((h >> 16) == 0xC0A8) ||
           ((h >> 20) == 0xAC1);
}

// ─────────────────────────────────────────────────────────────────────
//  Geolocation (ip-api.com, 비동기)
// ─────────────────────────────────────────────────────────────────────

std::mutex geo_mutex;
std::map<std::string, std::string> geo_cache;

static std::string geolocate(const std::string& ip) {
    if (is_private_ip(ip)) return "";
    {
        std::lock_guard<std::mutex> lk(geo_mutex);
        auto it = geo_cache.find(ip);
        if (it != geo_cache.end()) return it->second;
    }

    /* curl 인수에 ip 직접 삽입 전 inet_pton으로 검증 완료 */
    std::string cmd = "curl -s --max-time 4 'http://ip-api.com/json/" +
                      ip + "?fields=status,country,city' 2>/dev/null";
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";

    char buf[512] = {};
    fread(buf, 1, sizeof(buf) - 1, pipe);
    pclose(pipe);

    std::string raw(buf);
    auto extract = [&](const std::string& key) -> std::string {
        std::string needle = "\"" + key + "\":\"";
        auto pos = raw.find(needle);
        if (pos == std::string::npos) return "";
        pos += needle.size();
        auto end = raw.find('"', pos);
        return end != std::string::npos ? raw.substr(pos, end - pos) : "";
    };

    std::string loc;
    if (extract("status") == "success") {
        std::string country = extract("country");
        std::string city    = extract("city");
        if (!country.empty())
            loc = city.empty() ? country : (city + ", " + country);
    }

    std::lock_guard<std::mutex> lk(geo_mutex);
    geo_cache[ip] = loc;
    return loc;
}

// ─────────────────────────────────────────────────────────────────────
//  UI 메시지 큐 (모든 스레드 → UI 스레드)
// ─────────────────────────────────────────────────────────────────────

struct LogEntry { std::string text; int color_pair; bool bold; };

std::queue<LogEntry> g_ui_queue;
std::mutex           g_ui_queue_mtx;

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
    init_pair(CP_BORDER_NORMAL, COLOR_WHITE,   -1);
    init_pair(CP_BORDER_ALERT,  COLOR_RED,     -1);
    init_pair(CP_TITLE_NORMAL,  COLOR_CYAN,    -1);
    init_pair(CP_TITLE_ALERT,   COLOR_RED,     -1);
    init_pair(CP_LINE_ALERT,    COLOR_YELLOW,  -1);
    init_pair(CP_STATUSBAR,     COLOR_BLACK,   COLOR_WHITE);
    init_pair(CP_SELECTED,      COLOR_GREEN,   -1);
    init_pair(CP_SYSTEM,        COLOR_CYAN,    -1);
    init_pair(CP_CRITICAL,      COLOR_RED,     -1);
    init_pair(CP_RISK_HIGH,     COLOR_YELLOW,  -1);
    init_pair(CP_RISK_MED,      COLOR_CYAN,    -1);
    init_pair(CP_RISK_LOW,      COLOR_WHITE,   -1);
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
//  오버레이 창
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
        wattron(win, COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvwhline(win, 0, 0, ' ', cols);
        mvwprintw(win, 0, 1, " %s", title.c_str());
        wattroff(win, COLOR_PAIR(CP_STATUSBAR) | A_BOLD);

        for (int i = 0; i < view_h - 1 && scroll + i < total; i++) {
            const std::string& line = lines[scroll + i];
            bool is_alert = (line.find("ALERT:") != std::string::npos);
            bool is_geo   = (line.find("[GEO]") != std::string::npos);
            if (is_alert)     wattron(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
            else if (is_geo)  wattron(win, COLOR_PAIR(CP_CRITICAL) | A_BOLD);
            int cw = cols - 2;
            std::string disp = line.size() > (size_t)cw ? line.substr(0, cw) : line;
            mvwprintw(win, i + 1, 1, "%-*s", cw, disp.c_str());
            if (is_alert || is_geo) wattroff(win, COLOR_PAIR(CP_LINE_ALERT) | COLOR_PAIR(CP_CRITICAL) | A_BOLD);
        }

        wattron(win, COLOR_PAIR(CP_STATUSBAR));
        mvwhline(win, rows - 1, 0, ' ', cols);
        mvwprintw(win, rows - 1, 1,
                  " %d/%d  UP/DOWN: scroll  Ctrl+B/F | PgUp/PgDn: page  Home/End  q: close",
                  std::min(scroll + view_h - 1, total), total);
        wattroff(win, COLOR_PAIR(CP_STATUSBAR));

        wrefresh(win);
        int ch = wgetch(win);
        if (ch == 'q' || ch == 'Q') break;
        if (ch == KEY_UP   && scroll > 0) scroll--;
        if (ch == KEY_DOWN && scroll + view_h - 1 < total) scroll++;
        if (ch == KEY_PPAGE || ch == 2)  scroll = std::max(0, scroll - (view_h - 1));
        if (ch == KEY_NPAGE || ch == 6)  scroll = std::min(std::max(0, total - view_h + 1), scroll + view_h - 1);
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
//  로그 기록 + 위험도/버스트 업데이트
// ─────────────────────────────────────────────────────────────────────

/* REVERSE_SHELL 메시지에서 remote IP 추출: "remote=1.2.3.4:4444" */
static std::string extract_remote_ip(const std::string& msg) {
    auto pos = msg.find("remote=");
    if (pos == std::string::npos) return "";
    pos += 7;
    auto colon = msg.find(':', pos);
    auto space  = msg.find(' ',  pos);
    auto end    = std::min(colon, space);
    return (end != std::string::npos) ? msg.substr(pos, end - pos) : msg.substr(pos);
}

void log_message(const std::string& ip, const std::string& msg) {
    std::time_t now = std::time(nullptr);
    char tbuf[32];
    std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    /* central 파일 저장 */
    {
        std::lock_guard<std::mutex> lk(log_file_mutex);
        std::ofstream f(MASTER_LOG_FILE, std::ios::app);
        if (f.is_open())
            f << "[" << tbuf << "] [Agent: " << ip << "] " << msg << "\n";

        /* per-agent 파일 저장: agents/{ip}.log */
        std::string safe_ip = ip;
        std::replace(safe_ip.begin(), safe_ip.end(), ':', '_'); /* IPv6 대비 */
        std::string agent_path = AGENT_LOG_DIR + "/" + safe_ip + ".log";
        std::ofstream af(agent_path, std::ios::app);
        if (af.is_open())
            af << "[" << tbuf << "] " << msg << "\n";
    }

    /* per-agent 업데이트 */
    bool is_alert    = (msg.find("ALERT:")        != std::string::npos);
    bool is_reverse  = (msg.find("REVERSE_SHELL") != std::string::npos);
    bool is_webshell = (msg.find("WEBSHELL")      != std::string::npos);
    bool is_file     = (msg.find("FILE ACCESS")   != std::string::npos);
    bool burst_triggered = false;

    {
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        auto& d = agent_data[ip];
        d.logs.push_back(msg);
        if (d.logs.size() > MAX_LOG_LINES) d.logs.pop_front();
        d.last_seen = std::time(nullptr);

        /* 그래프용 이벤트 타임라인 업데이트 (타입별 분리) */
        auto trim_deque = [&](std::deque<std::time_t>& dq) {
            while (!dq.empty() && now - dq.front() > GRAPH_WINDOW_SEC)
                dq.pop_front();
        };

        /* 위험도 가중치 + 타입별 타임스탬프 */
        if (is_reverse) {
            d.risk = std::min(100, d.risk + 30); d.cnt_reverse++;
            d.reverse_times.push_back(now); trim_deque(d.reverse_times);
        } else if (is_webshell) {
            d.risk = std::min(100, d.risk + 25); d.cnt_webshell++;
            d.webshell_times.push_back(now); trim_deque(d.webshell_times);
        } else if (is_file) {
            d.risk = std::min(100, d.risk +  2); d.cnt_file++;
            d.file_times.push_back(now); trim_deque(d.file_times);
        } else if (msg.find("EXEC") != std::string::npos) {
            d.risk = std::min(100, d.risk +  1); d.cnt_exec++;
            d.exec_times.push_back(now); trim_deque(d.exec_times);
        }

        /* ALERT 버스트 감지 */
        if (is_alert) {
            d.alert = true;
            std::time_t now = std::time(nullptr);
            d.alert_ts.push_back(now);
            while (!d.alert_ts.empty() && now - d.alert_ts.front() > BURST_WINDOW)
                d.alert_ts.pop_front();
            if ((int)d.alert_ts.size() >= BURST_THRESH && !d.critical) {
                d.critical = true;
                burst_triggered = true;
            }
        }
    }

    /* UI 출력 */
    std::string line = "[" + display_name(ip) + "] " + msg;
    if (is_alert)
        ui_enqueue(line, CP_LINE_ALERT, true);
    else
        ui_enqueue(line);

    if (burst_triggered)
        ui_enqueue("!! ALERT BURST: " + display_name(ip) + " — " +
                   std::to_string(BURST_THRESH) + " alerts in " +
                   std::to_string(BURST_WINDOW) + "s !!",
                   CP_CRITICAL, true);

    /* Geolocation: REVERSE_SHELL인 경우 비동기 조회 */
    if (is_reverse) {
        std::string remote_ip = extract_remote_ip(msg);
        if (!remote_ip.empty()) {
            std::thread([ip, remote_ip]() {
                std::string loc = geolocate(remote_ip);
                if (loc.empty()) return;
                std::string geo_msg = "[GEO] " + remote_ip + " -> " + loc;
                ui_enqueue(geo_msg, CP_CRITICAL, true);
                {
                    std::lock_guard<std::mutex> lk(log_file_mutex);
                    std::ofstream f(MASTER_LOG_FILE, std::ios::app);
                    if (f.is_open()) {
                        std::time_t now = std::time(nullptr);
                        char tbuf[32];
                        std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S",
                                      std::localtime(&now));
                        f << "[" << tbuf << "] [Agent: " << ip << "] " << geo_msg << "\n";
                    }
                }
            }).detach();
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
        if (connected) {
            auto& d = agent_data[ip];
            d.last_seen = std::time(nullptr);
        }
    }
    std::string msg = connected
        ? "[SYSTEM] Agent connected: "    + display_name(ip)
        : "[SYSTEM] Agent disconnected: " + display_name(ip);
    ui_enqueue(msg, CP_SYSTEM, true);
}

// ─────────────────────────────────────────────────────────────────────
//  Risk Score 비율 감쇠 (exponential decay)
// ─────────────────────────────────────────────────────────────────────

#define DECAY_INTERVAL_SEC  60      /* 감쇠 주기 (초) */
#define DECAY_FACTOR        0.7     /* 주기마다 risk × 0.7 */
#define RISK_MIN_THRESHOLD  2       /* 이 값 이하면 0으로 정리 */

void risk_decay_loop() {
    while (true) {
        /* DECAY_INTERVAL_SEC 동안 1초씩 쪼개서 sleep (종료 시 빠른 반응 위해) */
        for (int i = 0; i < DECAY_INTERVAL_SEC; i++) sleep(1);

        std::time_t now = std::time(nullptr);
        std::lock_guard<std::mutex> lk(agent_data_mutex);
        for (auto& [ip, d] : agent_data) {
            /* risk 감쇠 */
            if (d.risk > 0) {
                d.risk = (int)(d.risk * DECAY_FACTOR);
                if (d.risk <= RISK_MIN_THRESHOLD) d.risk = 0;
            }

            /* burst 윈도우 만료 시 CRITICAL 자동 해제 */
            if (d.critical) {
                while (!d.alert_ts.empty() &&
                       now - d.alert_ts.front() > BURST_WINDOW)
                    d.alert_ts.pop_front();
                if (d.alert_ts.size() < (size_t)BURST_THRESH) {
                    d.critical = false;
                    ui_enqueue("[SYSTEM] CRITICAL cleared: " + display_name(ip),
                               CP_SYSTEM, true);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  TUI Dashboard (tm)
// ─────────────────────────────────────────────────────────────────────

struct PanelLayout { int y, x, h, w; };

/* 그래프 모드 전역 플래그 (run_dashboard에서만 읽기/쓰기 → 별도 뮤텍스 불필요) */
static bool g_graph_mode = false;

/* 이벤트 타임스탬프 deque를 버킷 배열로 변환 */
static std::vector<int> make_buckets(const std::deque<std::time_t>& times,
                                     int n_buckets, std::time_t now) {
    std::vector<int> b(n_buckets, 0);
    for (auto t : times) {
        int age = (int)(now - t);
        if (age < 0 || age >= GRAPH_WINDOW_SEC) continue;
        int idx = (int)((double)(GRAPH_WINDOW_SEC - 1 - age)
                        / GRAPH_WINDOW_SEC * n_buckets);
        if (idx >= 0 && idx < n_buckets) b[idx]++;
    }
    return b;
}

/* 라벨별 스파크라인 한 행 그리기
 * density 값에 따라 ' ' / '.' / '+' / '#' 문자 사용 */
static void draw_sparkline_row(WINDOW *win, int row, int label_w, int bar_w,
                               const char *label, int color_pair,
                               const std::vector<int>& buckets) {
    /* 라벨 */
    wattron(win, COLOR_PAIR(color_pair) | A_BOLD);
    mvwprintw(win, row, 1, "%-*s", label_w, label);
    wattroff(win, COLOR_PAIR(color_pair) | A_BOLD);

    int max_val = *std::max_element(buckets.begin(), buckets.end());

    /* 스파크라인 바 */
    wattron(win, COLOR_PAIR(color_pair));
    int x = 1 + label_w;
    for (int col = 0; col < (int)buckets.size() && col < bar_w; col++) {
        char ch;
        if (max_val == 0 || buckets[col] == 0) ch = ' ';
        else {
            double ratio = (double)buckets[col] / max_val;
            ch = (ratio > 0.66) ? '#'
               : (ratio > 0.33) ? '+'
                                 : '.';
        }
        mvwaddch(win, row, x + col, ch);
    }
    wattroff(win, COLOR_PAIR(color_pair));
}

/* 패널 내부에 이벤트 종류별 스파크라인 렌더링
 *
 * EXEC    [##.#  +#. ##  +#  ...]
 * FILE    [+# .## +# .##  +# ...]
 * REVERSE [          ##        .]
 * WEB     [     .               ]
 *          60s ago           now
 */
static void draw_graph(WINDOW *win, const AgentData& d,
                       int start_row, int area_h, int area_w) {
    if (area_h <= 0 || area_w <= 0) return;

    /* 구조: 라벨(8자) + 스파크라인 + 시간눈금 1줄 */
    const int LABEL_W = 8;
    int bar_w   = area_w - LABEL_W;
    if (bar_w < 4) return;

    /* 이벤트 4종 정의 */
    struct Row {
        const char *label;
        int         color;
        const std::deque<std::time_t>& times;
    };
    Row rows[] = {
        { "EXEC",    CP_BORDER_NORMAL, d.exec_times    },
        { "FILE",    CP_RISK_LOW,      d.file_times    },
        { "REVERSE", CP_CRITICAL,      d.reverse_times },
        { "WEB",     CP_RISK_HIGH,     d.webshell_times},
    };
    int n_rows = (int)(sizeof(rows) / sizeof(rows[0]));

    std::time_t now = std::time(nullptr);

    for (int r = 0; r < n_rows && r < area_h - 1; r++) {
        auto buckets = make_buckets(rows[r].times, bar_w, now);
        draw_sparkline_row(win, start_row + r, LABEL_W, bar_w,
                           rows[r].label, rows[r].color, buckets);
    }

    /* 시간 눈금 */
    int axis_row = start_row + n_rows;
    if (axis_row < getmaxy(win) - 1 && axis_row < start_row + area_h) {
        wattron(win, A_DIM);
        mvwprintw(win, axis_row, 1 + LABEL_W, "%-*s", bar_w - 3, "60s ago");
        mvwprintw(win, axis_row, 1 + LABEL_W + bar_w - 3, "now");
        wattroff(win, A_DIM);
    }
}

static std::vector<PanelLayout> calc_layout(int n, int rows, int cols) {
    int u = rows - 1;
    std::vector<PanelLayout> L;
    if (n == 1) {
        L.push_back({0, 0, u, cols});
    } else if (n == 2) {
        int hw = cols / 2;
        L.push_back({0, 0,  u, hw});
        L.push_back({0, hw, u, cols - hw});
    } else if (n == 3) {
        int hh = u / 2, hw = cols / 2;
        L.push_back({0,  0,  hh,     hw});
        L.push_back({0,  hw, hh,     cols - hw});
        L.push_back({hh, 0,  u - hh, cols});
    } else {
        int hh = u / 2, hw = cols / 2;
        L.push_back({0,  0,  hh,     hw});
        L.push_back({0,  hw, hh,     cols - hw});
        L.push_back({hh, 0,  u - hh, hw});
        L.push_back({hh, hw, u - hh, cols - hw});
    }
    return L;
}

static void draw_panel(WINDOW *win, const std::string& ip, const AgentData& d) {
    int h, w;
    getmaxyx(win, h, w);
    werase(win);

    bool crit = d.critical;
    bool alrt = d.alert;

    /* 테두리 */
    int border_cp = crit ? CP_CRITICAL : (alrt ? CP_BORDER_ALERT : CP_BORDER_NORMAL);
    wattron(win, COLOR_PAIR(border_cp) | ((crit || alrt) ? A_BOLD : 0));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(border_cp) | A_BOLD);

    /* 타이틀 */
    std::string dname = display_name(ip);
    std::string title = crit ? (" !! " + dname + " !! ")
                       : alrt ? (" ! " + dname + " ! ")
                               : (" " + dname + " ");
    int tx = std::max(1, (w - (int)title.size()) / 2);
    int title_cp = crit ? CP_CRITICAL : (alrt ? CP_TITLE_ALERT : CP_TITLE_NORMAL);
    wattron(win, COLOR_PAIR(title_cp) | A_BOLD);
    mvwprintw(win, 0, tx, "%s", title.c_str());
    wattroff(win, COLOR_PAIR(title_cp) | A_BOLD);

    /* 위험도 + 모드 표시 (1행) */
    if (h > 4) {
        char rbuf[48];
        snprintf(rbuf, sizeof(rbuf), " RISK:%d [%s]%s ",
                 d.risk, risk_label(d.risk),
                 g_graph_mode ? " | GRAPH" : "");
        int rx = std::max(1, (w - (int)strlen(rbuf)) / 2);
        wattron(win, COLOR_PAIR(risk_color(d.risk)) | A_BOLD);
        mvwprintw(win, 1, rx, "%s", rbuf);
        wattroff(win, COLOR_PAIR(risk_color(d.risk)) | A_BOLD);
    }

    int content_start = (h > 4) ? 2 : 1;
    int area_h = h - content_start - 1;   /* 테두리 하단 1줄 제외 */
    int area_w = w - 2;

    if (g_graph_mode) {
        /* 그래프 뷰 */
        draw_graph(win, d, content_start, area_h, area_w);
    } else {
        /* 로그 뷰 */
        int start = (int)d.logs.size() > area_h
                    ? (int)d.logs.size() - area_h : 0;
        for (int i = 0; i < area_h && start + i < (int)d.logs.size(); i++) {
            std::string line = d.logs[start + i];
            if ((int)line.size() > area_w) line = line.substr(0, area_w);
            bool la = (line.find("ALERT:") != std::string::npos);
            if (la) wattron(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
            mvwprintw(win, content_start + i, 1, "%-*s", area_w, line.c_str());
            if (la) wattroff(win, COLOR_PAIR(CP_LINE_ALERT) | A_BOLD);
        }
    }
    wrefresh(win);
}

static void draw_statusbar_tm(int rows, int cols,
                              int n_agents, int n_alerts, int n_critical) {
    char tbuf[32];
    time_t now = time(nullptr);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    std::string left = std::string(" ") + tbuf +
                       "  Agents:" + std::to_string(n_agents) +
                       "  Alerts:" + std::to_string(n_alerts);
    if (n_critical > 0)
        left += "  !! CRITICAL:" + std::to_string(n_critical) + " !!";

    std::string right = std::string(g_graph_mode ? "[g]log " : "[g]graph ") + "[c]lear  [q]uit ";
    int pad = cols - (int)left.size() - (int)right.size();
    std::string bar = left + std::string(std::max(0, pad), ' ') + right;
    if ((int)bar.size() > cols) bar = bar.substr(0, cols);

    int cp = (n_critical > 0) ? CP_CRITICAL : CP_STATUSBAR;
    attron(COLOR_PAIR(cp) | A_REVERSE | A_BOLD);
    mvprintw(rows - 1, 0, "%s", bar.c_str());
    attroff(COLOR_PAIR(cp) | A_REVERSE | A_BOLD);
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
        if (ch == 'g' || ch == 'G') {
            g_graph_mode = !g_graph_mode;
        }
        if (ch == 'c' || ch == 'C') {
            std::lock_guard<std::mutex> lk(agent_data_mutex);
            for (auto& ip : ips) {
                if (agent_data.count(ip)) {
                    agent_data[ip].alert    = false;
                    agent_data[ip].critical = false;
                    agent_data[ip].alert_ts.clear();
                }
            }
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

        int n_alerts = 0, n_critical = 0;
        for (int i = 0; i < n; i++) {
            AgentData snap;
            {
                std::lock_guard<std::mutex> lk(agent_data_mutex);
                if (agent_data.count(ips[i])) snap = agent_data[ips[i]];
            }
            if (snap.alert)    n_alerts++;
            if (snap.critical) n_critical++;
            draw_panel(wins[i], ips[i], snap);
        }
        draw_statusbar_tm(rows, cols, n, n_alerts, n_critical);
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
            AgentData snap;
            {
                std::lock_guard<std::mutex> lk(agent_data_mutex);
                if (agent_data.count(all[i])) snap = agent_data[all[i]];
            }
            if (i == cursor) attron(A_REVERSE);
            if (checked[i]) attron(COLOR_PAIR(CP_SELECTED));
            mvprintw(i + 3, 4, "[%c] %-25s  RISK:%3d [%s]  %s",
                     checked[i] ? 'x' : ' ',
                     display_name(all[i]).c_str(),
                     snap.risk,
                     risk_label(snap.risk),
                     time_ago(snap.last_seen).c_str());
            if (checked[i]) attroff(COLOR_PAIR(CP_SELECTED));
            if (i == cursor) attroff(A_REVERSE);
        }
        refresh();

        int ch = getch();
        switch (ch) {
        case KEY_UP:   cursor = std::max(0, cursor - 1); break;
        case KEY_DOWN: cursor = std::min((int)all.size() - 1, cursor + 1); break;
        case ' ':      checked[cursor] = !checked[cursor]; break;
        case 'a': case 'A': std::fill(checked.begin(), checked.end(), true); break;
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
//  인터랙티브 태그 UI
// ─────────────────────────────────────────────────────────────────────

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
        if (ch == 27) { buf[0] = '\0'; break; }
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
    if (agents.empty()) { ui_enqueue("No connected agents.", CP_SYSTEM, true); return; }

    curs_set(0);
    int cursor = 0;
    std::string selected_ip;

    while (true) {
        clear();
        attron(COLOR_PAIR(CP_STATUSBAR) | A_BOLD);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 2, " Tag Agent - Select agent");
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
        if (ch == 'q' || ch == 'Q') goto tag_done;
        if (ch == KEY_UP)   cursor = std::max(0, cursor - 1);
        if (ch == KEY_DOWN) cursor = std::min((int)agents.size() - 1, cursor + 1);
        if (ch == '\n' || ch == KEY_ENTER) { selected_ip = agents[cursor]; break; }
    }
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
                g_tag_to_ip[name]        = selected_ip;
                g_ip_to_tag[selected_ip] = name;
            }
            save_tags();
            ui_enqueue("Tagged: " + selected_ip + " -> " + name, CP_SYSTEM, true);
        }
    }
tag_done:
    restore_ui();
    keypad(g_cmd_win, TRUE);
    wtimeout(g_cmd_win, 100);
}

static void cmd_untag_interactive() {
    std::vector<std::pair<std::string, std::string>> tagged;
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        for (auto& [name, ip] : g_tag_to_ip) tagged.push_back({name, ip});
    }
    if (tagged.empty()) { ui_enqueue("No tags defined.", CP_SYSTEM, true); return; }

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
//  명령어 핸들러
// ─────────────────────────────────────────────────────────────────────

static void cmd_trace_log(const std::string& target) {
    std::string ip = resolve_ip(target);
    std::ifstream f(MASTER_LOG_FILE);
    if (!f.is_open()) { ui_enqueue("Cannot open " + MASTER_LOG_FILE, CP_BORDER_ALERT, true); return; }
    std::string needle = "[Agent: " + ip + "]";
    std::vector<std::string> results;
    std::string line;
    while (std::getline(f, line))
        if (line.find(needle) != std::string::npos) results.push_back(line);
    show_overlay("trace-log: " + target + " (" + ip + ")  [" +
                 std::to_string(results.size()) + " entries]", results);
}

static void cmd_trace_tr(const std::string& range) {
    int sh = -1, eh = -1;
    if (sscanf(range.c_str(), "%d:%d", &sh, &eh) != 2 ||
        sh < 0 || sh > 23 || eh < 0 || eh > 23) {
        ui_enqueue("Usage: trace-tr <H:H>  e.g. trace-tr 1:13", CP_SYSTEM, true); return;
    }
    std::ifstream f(MASTER_LOG_FILE);
    if (!f.is_open()) { ui_enqueue("Cannot open " + MASTER_LOG_FILE, CP_BORDER_ALERT, true); return; }
    std::vector<std::string> results;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("ALERT:") == std::string::npos) continue;
        if (line.size() < 14 || line[0] != '[') continue;
        int hour = -1;
        sscanf(line.c_str() + 12, "%d", &hour);
        if (hour < 0) continue;
        bool in = (sh <= eh) ? (hour >= sh && hour <= eh)
                              : (hour >= sh || hour <= eh);
        if (in) results.push_back(line);
    }
    char title[128];
    snprintf(title, sizeof(title), "trace-tr %02d:00~%02d:00  [%d ALERTs]",
             sh, eh, (int)results.size());
    show_overlay(title, results);
}

static void cmd_stats(const std::string& target) {
    std::vector<std::string> ips;
    if (target.empty()) {
        std::lock_guard<std::mutex> lk(clients_mutex);
        ips.assign(connected_agents.begin(), connected_agents.end());
    } else {
        ips.push_back(resolve_ip(target));
    }

    std::vector<std::string> lines;
    const int BAR_W = 28;

    auto make_bar = [&](const char* label, int cnt, int max_cnt) {
        int filled = (max_cnt > 0) ? cnt * BAR_W / max_cnt : 0;
        std::string bar(filled, '#');
        bar += std::string(BAR_W - filled, '-');
        char buf[128];
        snprintf(buf, sizeof(buf), "  %-12s |%s| %d", label, bar.c_str(), cnt);
        return std::string(buf);
    };

    for (auto& ip : ips) {
        AgentData snap;
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(agent_data_mutex);
            auto it = agent_data.find(ip);
            if (it != agent_data.end()) { snap = it->second; found = true; }
        }
        if (!found) { lines.push_back("Agent not found: " + ip); continue; }

        lines.push_back("Agent    : " + display_name(ip));
        lines.push_back("Last seen: " + time_ago(snap.last_seen));
        lines.push_back("Risk     : " + std::to_string(snap.risk) +
                         " [" + risk_label(snap.risk) + "]" +
                         (snap.critical ? "  !! BURST DETECTED !!" : ""));
        lines.push_back("");

        int mx = std::max({snap.cnt_exec, snap.cnt_file,
                           snap.cnt_reverse, snap.cnt_webshell, 1});
        lines.push_back(make_bar("EXEC",        snap.cnt_exec,     mx));
        lines.push_back(make_bar("FILE ACCESS", snap.cnt_file,     mx));
        lines.push_back(make_bar("REV SHELL",   snap.cnt_reverse,  mx));
        lines.push_back(make_bar("WEBSHELL",    snap.cnt_webshell, mx));
        lines.push_back("");
    }

    show_overlay("stats" + (target.empty() ? " (all)" : ": " + target), lines);
}

static void cmd_tag(const std::string& ip, const std::string& name) {
    if (ip.empty() || name.empty()) { ui_enqueue("Usage: tag <ip> <name>", CP_SYSTEM, true); return; }
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        auto old = g_ip_to_tag.find(ip);
        if (old != g_ip_to_tag.end()) g_tag_to_ip.erase(old->second);
        g_tag_to_ip[name] = ip;
        g_ip_to_tag[ip]   = name;
    }
    save_tags();
    ui_enqueue("Tagged: " + ip + " -> " + name, CP_SYSTEM, true);
}

static void cmd_untag(const std::string& name) {
    if (name.empty()) { ui_enqueue("Usage: untag <name>", CP_SYSTEM, true); return; }
    {
        std::lock_guard<std::mutex> lk(tag_mutex);
        auto it = g_tag_to_ip.find(name);
        if (it == g_tag_to_ip.end()) { ui_enqueue("Tag not found: " + name, CP_BORDER_ALERT, true); return; }
        g_ip_to_tag.erase(it->second);
        g_tag_to_ip.erase(it);
    }
    save_tags();
    ui_enqueue("Removed tag: " + name, CP_SYSTEM, true);
}

static void cmd_tags() {
    std::lock_guard<std::mutex> lk(tag_mutex);
    if (g_tag_to_ip.empty()) { ui_enqueue("No tags. Use: tag <ip> <name>", CP_SYSTEM, false); return; }
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
        ui_flush();
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
                std::vector<std::string> agents;
                {
                    std::lock_guard<std::mutex> lk(clients_mutex);
                    agents.assign(connected_agents.begin(), connected_agents.end());
                }
                ui_enqueue("--- Connected Agents (" + std::to_string(agents.size()) + ") ---",
                           CP_TITLE_NORMAL, true);
                for (auto& a : agents) {
                    AgentData snap;
                    {
                        std::lock_guard<std::mutex> lk(agent_data_mutex);
                        if (agent_data.count(a)) snap = agent_data[a];
                    }
                    char buf[128];
                    snprintf(buf, sizeof(buf), "  %-30s  RISK:%3d [%-8s]  %s",
                             display_name(a).c_str(),
                             snap.risk, risk_label(snap.risk),
                             time_ago(snap.last_seen).c_str());
                    int cp = risk_color(snap.risk);
                    ui_enqueue(buf, cp, snap.risk >= 50);
                }
                ui_enqueue("---------------------------------------------");

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
                auto sel = select_agents_tui();
                if (!sel.empty()) { clear(); refresh(); run_dashboard(sel); }
                restore_ui();
                keypad(g_cmd_win, TRUE);
                wtimeout(g_cmd_win, 100);

            } else if (cmd == "trace-log") {
                if (arg1.empty()) ui_enqueue("Usage: trace-log <ip|tag>", CP_SYSTEM, true);
                else cmd_trace_log(arg1);

            } else if (cmd == "trace-tr") {
                if (arg1.empty()) ui_enqueue("Usage: trace-tr <H:H>  e.g. 1:13", CP_SYSTEM, true);
                else cmd_trace_tr(arg1);

            } else if (cmd == "stats") {
                cmd_stats(arg1);

            } else if (cmd == "help") {
                ui_enqueue("  list                 : 에이전트 목록 + 위험도 + 마지막 수신", CP_SYSTEM, false);
                ui_enqueue("  tag [<ip> <name>]    : 태그 지정 (인수 없으면 선택 UI)",       CP_SYSTEM, false);
                ui_enqueue("  untag [<name>]       : 태그 제거 (인수 없으면 선택 UI)",       CP_SYSTEM, false);
                ui_enqueue("  tags                 : 태그 목록",                             CP_SYSTEM, false);
                ui_enqueue("  tm                   : Trace Monitor 대시보드",                CP_SYSTEM, false);
                ui_enqueue("  stats [ip|tag]       : 이벤트 통계 + ASCII 바 차트",           CP_SYSTEM, false);
                ui_enqueue("  trace-log <ip|tag>   : 에이전트 전체 로그 조회",               CP_SYSTEM, false);
                ui_enqueue("  trace-tr  <H:H>      : 시간대 ALERT 조회 (e.g. 1:13)",        CP_SYSTEM, false);
                ui_enqueue("  exit                 : 서버 종료",                             CP_SYSTEM, false);

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
    if (SSL_accept(ssl) <= 0) { SSL_free(ssl); close(client_socket); return; }

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

    /* per-agent 로그 디렉토리 생성 */
    mkdir(AGENT_LOG_DIR.c_str(), 0755);

    load_tags();
    init_ui();
    ui_enqueue("Renux Master started on port " + std::to_string(PORT), CP_SYSTEM, true);

    std::thread(command_shell).detach();
    std::thread(risk_decay_loop).detach();

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
