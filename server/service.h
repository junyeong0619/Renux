#ifndef SERVICE_H
#define SERVICE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>

char *get_username(void);
int   is_valid_login(char *username, char *passwd, const char *server_passwd_hash);
void  handle_client_request(SSL *ssl, char *buffer, const char *username);

#endif // SERVICE_H
