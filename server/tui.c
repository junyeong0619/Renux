//
// Created by Junyeong on 2025. 9. 2..
//

#include "tui.h"
#include "../utils/log.h"
#include <string.h>
#include <locale.h>
#include <stdlib.h>

static WINDOW *log_win_border;
static WINDOW *log_win;
static WINDOW *input_win;

void init_server_tui() {
    setlocale(LC_ALL, "ko_KR.UTF-8");
    initscr();

    if (has_colors() == FALSE) {
        endwin();
        printf("Your terminal does not support color\n");
        exit(1);
    }
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLUE);

    wbkgd(stdscr, COLOR_PAIR(1));

    cbreak();
    echo();
    keypad(stdscr, TRUE);

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    log_win_border = newwin(max_y - 3, max_x, 0, 0);
    box(log_win_border, 0, 0);
    wbkgd(log_win_border, COLOR_PAIR(1));
    wrefresh(log_win_border);

    log_win = newwin(max_y - 5, max_x - 2, 1, 1);
    scrollok(log_win, TRUE);
    wbkgd(log_win, COLOR_PAIR(1));

    input_win = newwin(3, max_x, max_y - 3, 0);
    box(input_win, 0, 0);
    wbkgd(input_win, COLOR_PAIR(1));
    mvwprintw(input_win, 1, 1, "input command: ");
    wrefresh(input_win);
}

void display_server_log(const char *log_msg) {
    file_log(log_msg); //logging
    wattron(log_win, COLOR_PAIR(1));
    wprintw(log_win, "\n %s", log_msg);
    wattroff(log_win, COLOR_PAIR(1));
    wrefresh(log_win);
}

inline void get_server_input(char *buffer, int max_len) {
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "input command: ");
    wrefresh(input_win);
    mvwgetstr(input_win, 1, 16, buffer);
}

void cleanup_server_tui() {
    endwin();
}

void update_client_count(int count) {
    int max_x = getmaxx(log_win_border);
    int start_pos = max_x - 15;

    mvwprintw(log_win_border, 0, start_pos, "             ");
    mvwprintw(log_win_border, 0, start_pos, "Connected: %d", count);
    wrefresh(log_win_border);
}
