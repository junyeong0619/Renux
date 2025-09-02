//
// Created by Junyeong on 2025. 9. 2..
//

#include "service.h"

#include <string.h>

char *get_username(void) {
    char *username = getlogin();
    char *return_username = malloc(strlen(username) + 1);
    strcpy(return_username, username);
    return return_username;
}

int is_valid_login(char *username,char *passwd, char *server_passwd) {
    if (username == NULL)
        return -1;
    char *target_username = get_username();
    printf("input pass:%s server pass:%s",passwd,server_passwd);
    if (strcmp(username, target_username) == 0) {
        free(target_username);
        printf("name suc");
        if (strcmp(server_passwd,passwd) == 0) {
            printf("pass suc");
            return 0;
        }
    }
    return -1;
}
