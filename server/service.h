//
// Created by Junyeong on 2025. 9. 2..
//

#ifndef SERVICE_H
#define SERVICE_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *get_username(void);
int is_valid_login(char *username, char *passwd, unsigned long server_passwd);
void execute_command(char *command);
void start_server_service(int client_socket);
void handle_client_request(int client_socket, char* buffer);




#endif //SERVICE_H
