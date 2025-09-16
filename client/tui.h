//
// Created by Junyeong on 2025. 9. 2..
//

#ifndef TUI_H
#define TUI_H
#include <ncurses.h>

typedef struct {
    WINDOW *recv_win_border;
    WINDOW *recv_win;
    WINDOW *send_win;
} ChatWindows;

void init_client_tui(ChatWindows *wins);
void display_chat_message(WINDOW *win, const char *sender, const char *message);
void get_client_input(WINDOW *win, const char *prompt, char *buffer, int max_len);
void cleanup_client_tui();
int show_user_menu(char **choices, int n_choices);
int user_manage_function_selections();
int disk_quota_menu();
int show_filesystem_menu(char **choices, int n_choices);
void redraw_main_tui(ChatWindows *wins);



#endif //TUI_H
