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

    if (has_colors() == FALSE) {
        endwin();
        printf("Your terminal does not support color\n");
        exit(1);
    }
    start_color();

    init_pair(1, COLOR_WHITE, COLOR_BLUE);
    init_pair(2, COLOR_WHITE, COLOR_BLUE);
    init_pair(3, COLOR_WHITE, COLOR_BLUE);

    wbkgd(stdscr, COLOR_PAIR(1));

    cbreak();
    echo();
    keypad(stdscr, TRUE);
    refresh();

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);


    wins->recv_win_border = newwin(max_y - 3, max_x, 0, 0);
    box(wins->recv_win_border, 0, 0);
    wbkgd(wins->recv_win_border, COLOR_PAIR(1));
    wrefresh(wins->recv_win_border);

    wins->recv_win = newwin(max_y - 5, max_x - 2, 1, 1);
    scrollok(wins->recv_win, TRUE);
    wbkgd(wins->recv_win, COLOR_PAIR(1));
    wrefresh(wins->recv_win);

    wins->send_win = newwin(3, max_x, max_y - 3, 0);
    keypad(wins->send_win, TRUE);
    wbkgd(wins->send_win, COLOR_PAIR(1));
    wrefresh(wins->send_win);
}

void display_chat_message(WINDOW *win, const char *sender, const char *message) {
    if (strcmp(sender, "system") == 0) {
        wattron(win, COLOR_PAIR(1));
    } else if (strcmp(sender, "server") == 0) {
        wattron(win, COLOR_PAIR(2));
    }

    wprintw(win, "\n [%s] %s", sender, message);

    if (strcmp(sender, "system") == 0) {
        wattroff(win, COLOR_PAIR(1));
    } else if (strcmp(sender, "server") == 0) {
        wattroff(win, COLOR_PAIR(2));
    }
    wrefresh(win);
}

inline void get_client_input(WINDOW *win, char *buffer, int max_len) {
    werase(win);
    box(win, 0, 0);
    mvwprintw(win, 1, 1, "com: ");
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

int user_manage_function_selections() {
    WINDOW *menu_win;
    int highlight = 0;
    int choice = -1;
    int c;

    char *choices[] = {
        "Get user information",
        "Get process list",
        "Sample 3"
    };
    int n_choices = 3;

    clear();
    mvprintw(0, 0, "Select an action. (Enter to confirm, 'q' to cancel)");
    refresh();

    int menu_height = n_choices + 4;
    int menu_width = MENU_WIDTH;
    int starty = (LINES - menu_height) / 2;
    int startx = (COLS - menu_width) / 2;
    menu_win = newwin(menu_height, menu_width, starty, startx);
    keypad(menu_win, TRUE);

    while (1) {
        box(menu_win, 0, 0);
        for (int i = 0; i < n_choices; ++i) {
            if (highlight == i) {
                wattron(menu_win, A_REVERSE);
                mvwprintw(menu_win, i + 2, 2, "%s", choices[i]);
                wattroff(menu_win, A_REVERSE);
            } else {
                mvwprintw(menu_win, i + 2, 2, "%s", choices[i]);
            }
        }
        wrefresh(menu_win);

        c = wgetch(menu_win);
        switch (c) {
            case KEY_UP:
                highlight = (highlight == 0) ? n_choices - 1 : highlight - 1;
            break;
            case KEY_DOWN:
                highlight = (highlight == n_choices - 1) ? 0 : highlight + 1;
            break;
            case 10:
                choice = highlight;
            break;
            case 'q':
                choice = -1;
            break;
        }

        if (choice != -1) {
            break;
        }
    }

    delwin(menu_win);
    touchwin(stdscr);
    refresh();

    return choice;
}

void cleanup_client_tui() {
    endwin();
}
