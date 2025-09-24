//
// Created by Junyeong on 2025. 9. 2..
//

#ifndef TUI_H
#define TUI_H

#include <ncurses.h>

void init_server_tui();
void display_server_log(const char *log_msg);
void get_server_input(char *buffer, int max_len);
void cleanup_server_tui();
void update_client_count(int count);


#endif //TUI_H
