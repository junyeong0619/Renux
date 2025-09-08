//
// Created by Junyeong on 2025. 9. 2..
//

#include "tui.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#define MENU_WIDTH 40


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

    //scroll page when the page going to be full
    scrollok(wins->recv_win, TRUE);

    box(wins->recv_win, 0, 0);
    wrefresh(wins->recv_win);

    wins->send_win = newwin(3, max_x, max_y - 3, 0);
    box(wins->send_win, 0, 0);
    mvwprintw(wins->send_win, 1, 1, "command:   ");
    wrefresh(wins->send_win);
}

void display_chat_message(WINDOW *win, const char *sender, const char *message) {
    wprintw(win, "\n [%s] %s", sender, message);

    box(win, 0, 0);

    wrefresh(win);
}

void get_client_input(WINDOW *win, char *buffer, int max_len) {
    werase(win);
    box(win, 0, 0);
    mvwprintw(win, 1, 1, "input: ");
    wrefresh(win);
    mvwgetstr(win, 1, 6, buffer);
}

static void print_menu(WINDOW *menu_win, int highlight, int offset, int items_per_page, int n_choices, char *choices[]) {
    int x = 2;
    int y = 2;
    box(menu_win, 0, 0);

    for (int i = 0; i < items_per_page; ++i) {
        int current_idx = offset + i;
        if (current_idx >= n_choices) {
            break;
        }

        if (highlight == current_idx + 1) {
            wattron(menu_win, A_REVERSE);
            mvwprintw(menu_win, y + i, x, "%s", choices[current_idx]);
            wattroff(menu_win, A_REVERSE);
        } else {
            mvwprintw(menu_win, y + i, x, "%s", choices[current_idx]);
        }
    }

    int max_y, max_x;
    getmaxyx(menu_win, max_y, max_x);
    int current_page = (offset / items_per_page) + 1;
    int total_pages = (n_choices + items_per_page - 1) / items_per_page;
    mvwprintw(menu_win, max_y - 2, x, "Page %d / %d", current_page, total_pages);

    wrefresh(menu_win);
}


int show_user_menu(char **choices, int n_choices) {
    WINDOW *menu_win;
    int highlight = 1;
    int choice = 0;
    int c;

    const int items_per_page = 5;
    int offset = 0;

    clear();
    refresh();

    int menu_height = items_per_page + 4;
    int menu_width = MENU_WIDTH;

    mvprintw(0, 0, "Use arrow keys to move, Enter to select.");
    int starty = (LINES - menu_height) / 2;
    int startx = (COLS - menu_width) / 2;
    menu_win = newwin(menu_height, menu_width, starty, startx);
    keypad(menu_win, TRUE);

    print_menu(menu_win, highlight, offset, items_per_page, n_choices, choices);

    while (1) {
        c = wgetch(menu_win);
        switch (c) {
            case KEY_UP:
                highlight = (highlight == 1) ? n_choices : highlight - 1;
            break;
            case KEY_DOWN:
                highlight = (highlight == n_choices) ? 1 : highlight + 1;
            break;
            case 10: // Enter key
                choice = highlight;
            break;
        }

        offset = ((highlight - 1) / items_per_page) * items_per_page;

        werase(menu_win);
        print_menu(menu_win, highlight, offset, items_per_page, n_choices, choices);

        if (choice != 0)
            break;
    }

    delwin(menu_win);
    touchwin(stdscr);
    refresh();

    return choice;
}

void cleanup_client_tui() {
    endwin();
}
