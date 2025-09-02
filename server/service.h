//
// Created by Junyeong on 2025. 9. 2..
//

#ifndef SERVICE_H
#define SERVICE_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *get_username(void);
int is_valid_login(char *username, char *passwd, char *server_passwd);



#endif //SERVICE_H
