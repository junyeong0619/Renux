//
// Created by Junyeong on 2025. 9. 2..
//

#include "tui.h"
#include <string.h>
#include <locale.h>

static WINDOW *log_win;
static WINDOW *input_win;

void init_server_tui() {
    setlocale(LC_ALL, "ko_KR.UTF-8");
    initscr();
    cbreak();
    echo();
    keypad(stdscr, TRUE);

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    log_win = newwin(max_y - 3, max_x, 0, 0);

    scrollok(log_win, TRUE);

    box(log_win, 0, 0);
    wrefresh(log_win);

    input_win = newwin(3, max_x, max_y - 3, 0);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "input command: ");
    wrefresh(input_win);
}

void display_server_log(const char *log_msg) {
    wprintw(log_win, "\n %s", log_msg);

    box(log_win, 0, 0);

    wrefresh(log_win);
}

void get_server_input(char *buffer, int max_len) {
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "input command: ");
    wrefresh(input_win);
    mvwgetstr(input_win, 1, 16, buffer);
}

void cleanup_server_tui() {
    endwin();
}
