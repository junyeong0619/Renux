//
// Created by Junyeong on 2025. 9. 2..
//

#include "tui.h"

#include <locale.h>
#include <string.h>

static int recv_row = 1;

void init_client_tui(ChatWindows *wins) {
    setlocale(LC_ALL, "ko_KR.UTF-8");
    initscr();
    cbreak();
    echo();
    keypad(stdscr, TRUE);
    refresh();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    wins->recv_win = newwin(max_y - 3, max_x, 0, 0);
    box(wins->recv_win, 0, 0);
    wrefresh(wins->recv_win);

    wins->send_win = newwin(3, max_x, max_y - 3, 0);
    box(wins->send_win, 0, 0);
    mvwprintw(wins->send_win, 1, 1, "input:   ");
    wrefresh(wins->send_win);
}

void display_chat_message(WINDOW *win, const char *sender, const char *message) {
    mvwprintw(win, recv_row++, 1, "[%s] %s", sender, message);
    wrefresh(win);
}

void get_client_input(WINDOW *win, char *buffer, int max_len) {
    werase(win);
    box(win, 0, 0);
    mvwprintw(win, 1, 1, "input: ");
    wrefresh(win);
    mvwgetstr(win, 1, 6, buffer);
}

void cleanup_client_tui() {
    endwin();
}
