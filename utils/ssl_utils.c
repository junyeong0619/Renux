#include "ssl_utils.h"

#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/*  djb2 해시 (하위 호환)                                               */
/* ------------------------------------------------------------------ */

unsigned long hash_string(const char *str) {
    unsigned long hash = 202411340;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* ------------------------------------------------------------------ */
/*  SHA-256 비밀번호 해싱                                               */
/* ------------------------------------------------------------------ */

void hash_password(const char *plain, char out_hex[65]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { out_hex[0] = '\0'; return; }

    unsigned char digest[32];
    unsigned int  digest_len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, plain, strlen(plain));
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < 32; i++) {
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    }
    out_hex[64] = '\0';
}

int verify_password(const char *plain, const char *stored_hex) {
    char computed[65];
    hash_password(plain, computed);
    return (strcmp(computed, stored_hex) == 0) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  TLS 컨텍스트                                                        */
/* ------------------------------------------------------------------ */

SSL_CTX *create_server_ssl_ctx(const char *cert_path, const char *key_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    /* TLS 1.2 이상만 허용 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* 불필요한 구형 옵션 비활성화 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "TLS: Certificate and key do not match.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

SSL_CTX *create_client_ssl_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    /* 자체 서명 인증서 허용 (트래픽은 암호화됨, 인증서 미검증) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

SSL_CTX *create_client_ssl_ctx_verified(const char *ca_cert_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    /* CA 인증서 로드 */
    if (SSL_CTX_load_verify_locations(ctx, ca_cert_path, NULL) <= 0) {
        fprintf(stderr, "TLS: Failed to load CA cert: %s\n", ca_cert_path);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* 서버 인증서 검증 필수 (mTLS) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;
}
