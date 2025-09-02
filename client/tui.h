//
// Created by Junyeong on 2025. 9. 2..
//

#ifndef TUI_H
#define TUI_H
#include <ncurses.h>

typedef struct {
    WINDOW *recv_win;
    WINDOW *send_win;
} ChatWindows;

void init_client_tui(ChatWindows *wins);
void display_chat_message(WINDOW *win, const char *sender, const char *message);
void get_client_input(WINDOW *win, char *buffer, int max_len);
void cleanup_client_tui();

#endif //TUI_H
