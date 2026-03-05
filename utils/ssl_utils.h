#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  비밀번호 해싱                                                        */
/* ------------------------------------------------------------------ */

/* djb2 해시 — 하위 호환용, 보안 목적으로는 아래 SHA-256 함수를 사용할 것 */
unsigned long hash_string(const char *str);

/* SHA-256 기반 해싱 / 검증 */
void hash_password(const char *plain, char out_hex[65]);
int  verify_password(const char *plain, const char *stored_hex);

/* ------------------------------------------------------------------ */
/*  TLS 컨텍스트                                                        */
/* ------------------------------------------------------------------ */

/*
 * create_server_ssl_ctx: 서버용 SSL_CTX 생성
 * cert_path — PEM 인증서 파일 경로 (e.g. /etc/renux/server.crt)
 * key_path  — PEM 개인키 파일 경로  (e.g. /etc/renux/server.key)
 * 실패 시 NULL 반환
 */
SSL_CTX *create_server_ssl_ctx(const char *cert_path, const char *key_path);

/*
 * create_client_ssl_ctx: 클라이언트용 SSL_CTX 생성
 * 자체 서명 인증서 허용 (SSL_VERIFY_NONE)
 * 실패 시 NULL 반환
 */
SSL_CTX *create_client_ssl_ctx(void);

/*
 * create_client_ssl_ctx_verified: 서버 인증서 검증 클라이언트 SSL_CTX 생성 (mTLS)
 * ca_cert_path — 서버의 CA(혹은 자체 서명) 인증서 경로
 *                e.g. /etc/renux/master.crt, /etc/renux/server.crt
 * 핸드셰이크 시 서버 인증서가 해당 CA로 서명되지 않으면 연결 거부.
 * 실패 시 NULL 반환
 */
SSL_CTX *create_client_ssl_ctx_verified(const char *ca_cert_path);

#ifdef __cplusplus
}
#endif

#endif // SSL_UTILS_H
