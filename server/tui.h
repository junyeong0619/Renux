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

/* 헤드리스 모드 플래그 (테스트 전용: -p <password> 인자 사용 시 활성화)
 * TUI 없이 stdout으로 로그를 출력하고 ncurses를 초기화하지 않는다. */
extern int headless_mode;


#endif //TUI_H
