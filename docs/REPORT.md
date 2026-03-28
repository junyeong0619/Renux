# Renux 구현 완료 보고서

**최초 작성:** 2026-03-03 (V2.0)
**최종 수정:** 2026-03-04 (V2.1 — 보안 검토 반영)
**기준 버전:** V1.0 → V2.1
**총 변경:** 12파일 수정 + 2파일 신규 생성 + 3파일 문서 신규

---

## 1. 개요

### V2.0 구현 범위 (2026-03-03)

V1.0 프로토타입에서 식별된 보안 취약점과 기능 한계를 4개 Phase로 나눠 순차 구현했습니다.

| Phase | 분류 | 목표 |
|---|---|---|
| 1 | Secure Coding | Command Injection 원천 차단 |
| 2 | System Hardening | 바이너리 자체 보안 강화 |
| 3 | Intelligent Monitoring | 위협 탐지 고도화 |
| 4 | Infrastructure | 통신 암호화 + 배포 자동화 |

### V2.1 추가 수정 (2026-03-04)

외부 기술 검토(REVIEW_ANALYSIS.md) 결과를 반영한 긴급 버그 수정 및 보안 강화.

| 항목 | 분류 |
|---|---|
| Signal Handler Race Condition 수정 | 버그 수정 |
| mTLS 서버 인증서 검증 적용 | 보안 강화 |
| Makefile macOS OpenSSL 경로 자동 감지 | 빌드 개선 |

---

## 2. Phase 1 — Secure Coding

### 문제 (V1.0)

`server/service.c`의 `popen()` 5곳이 모두 사용자 입력을 직접 쉘에 전달했습니다.

```c
// 취약 코드 예시 — target_user에 "; rm -rf /" 삽입 가능
snprintf(command, sizeof(command), "/usr/bin/renux trace %s", target_user);
pipe = popen(command, "r");  // 쉘 경유 → Command Injection
```

### 해결

#### 신규: `utils/exec_utils.h` / `utils/exec_utils.c`

`pipe() + fork() + execve()` 조합으로 **쉘을 완전히 배제**합니다.

```
popen("ps -u USER")          execve("/bin/ps", ["-u", "user"], env)
      ↓                    →         ↓
  /bin/sh -c "ps -u USER"        직접 커널 호출
  (메타문자 해석 가능)           (메타문자 인수로만 취급)
```

두 가지 인터페이스를 제공합니다:
- `exec_command(int fd, path, argv[])` — 일반 fd로 직접 스트리밍
- `exec_command_buf(path, argv[], &len)` — TLS 소켓용 버퍼 수집 (호출자 `free()`)

#### 변경: `server/service.c`

| 명령 | V1.0 | V2.0 |
|---|---|---|
| `trace` | `popen("/usr/bin/renux trace USER")` | `execve` 래퍼 |
| `get_proc` | `popen("ps -u USER")` | `execve` 래퍼 |
| `get_quota` | `popen("quota -u USER")` | `execve` 래퍼 |
| `set_quota` | `popen("setquota -u USER ...")` | `execve` 래퍼 |
| `getu` | `popen("awk -F: '{print $1}' /etc/passwd")` | `getpwent()` 직접 호출 |

#### 신규: 입력값 화이트리스트 검증

모든 사용자 입력이 `handle_client_request()` 진입 시 검증됩니다.

```c
// 사용자명: POSIX 규격 [a-z0-9_.-] 최대 32자
static int is_valid_username(const char *input);

// 쿼터 값: 숫자 + 단위 접미사(K/M/G/T)만 허용
static int is_valid_quota_value(const char *input);

// 파일시스템: '/'로 시작, 안전 문자만 허용
static int is_valid_filesystem(const char *input);
```

#### 변경: `monitoring/monitor.cpp`

`generate_diff()` 내부의 `popen("diff ...")` 제거 →
C++ 라인 비교로 대체하여 외부 프로세스 호출 없이 unified diff 출력.

---

## 3. Phase 2 — System Hardening

### 3-1. 컴파일 보안 플래그 (`Makefile`)

```makefile
# V1.0
CFLAGS = -g -Wall -std=gnu99

# V2.0
CFLAGS = -Wall -O2 -std=gnu99 -D_XOPEN_SOURCE=700 \
         -fstack-protector-all -D_FORTIFY_SOURCE=2 \
         -Wformat -Wformat-security

LDFLAGS = -Wl,-z,relro,-z,now   # Linux 전용 (uname 감지로 분기)
```

| 플래그 | 효과 |
|---|---|
| `-fstack-protector-all` | 스택 버퍼 오버플로 canary 삽입 |
| `-D_FORTIFY_SOURCE=2` | 위험한 libc 함수 런타임 검사 |
| `-Wformat-security` | 포맷 스트링 취약점 컴파일 경고 |
| `-z relro` | GOT 섹션 읽기 전용 고정 |
| `-z now` | 프로그램 시작 시 심볼 전부 resolve (lazy binding 비활성화) |

`renux_master`가 `all` 타겟에서 누락되어 있던 문제도 함께 수정했습니다.

### 3-2. Privilege Drop — `server/server.c` (Linux)

소켓 바인딩 + 이벤트 루프 등록 완료 후 모든 Linux capability를 드롭합니다.

```c
#ifdef __linux__
    cap_t caps = cap_init();      // 빈 capability 세트
    cap_set_proc(caps);           // 전부 드롭
    cap_free(caps);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // 이후 권한 재획득 차단
#endif
```

- 포트 8080은 1024 이상이므로 `CAP_NET_BIND_SERVICE`도 불필요
- `#ifdef __APPLE__` / `#elif __linux__` 기존 크로스플랫폼 구조 유지

---

## 4. Phase 3 — Intelligent Monitoring

### 4-1. 리버스 쉘 탐지 (`monitoring/monitor.cpp`)

30초 주기 독립 스레드에서 `/proc/net/tcp`를 파싱합니다.

```
탐지 흐름:
/proc/net/tcp (ESTABLISHED 상태)
    → 원격 IP가 외부 주소인 소켓의 inode 추출
    → /proc/[PID]/fd 역추적으로 소유 프로세스 특정
    → 프로세스명이 {bash, sh, nc, python, perl, ...} 이면 경보
    → write_agent_log("ALERT: REVERSE_SHELL DETECTED | pid=...")
```

### 4-2. 웹쉘 프로세스 트리 분석

같은 탐지 스레드에서 `/proc/[PID]/stat`의 PPID를 추적합니다.

```
탐지 패턴:
PPID comm ∈ {httpd, apache2, nginx, php-fpm, uwsgi}
PID  comm ∈ {sh, bash, dash, ...}
    → "ALERT: WEBSHELL SUSPECTED | parent=nginx -> child=bash"
```

### 4-3. 오프라인 로그 버퍼링

```
V1.0: 연결 실패 → return (로그 유실)
V2.0: 연결 실패 → queue에 push (최대 1000건)
      재연결 성공 → queue 전체 flush → 현재 메시지 전송
```

- `std::queue<std::string> offline_buffer` + `std::mutex net_mutex`
- inotify 루프와 탐지 스레드가 동시에 호출하므로 mutex 필수

---

## 5. Phase 4 — Infrastructure

### 5-1. SHA-256 비밀번호 해싱

기존 djb2 해시(`hash_string`)는 암호학적으로 취약합니다 (충돌 가능, brute-force 용이).

```
V1.0: unsigned long hash = djb2(passwd)
V2.0: char hash[65]      = SHA-256(passwd)   [OpenSSL EVP API]
```

변경된 함수 시그니처 체인:

```
ssl_utils.h  : hash_password() / verify_password() 추가
service.h    : is_valid_login(..., const char *server_passwd_hash)
service.c    : verify_password() 호출로 교체
server.c     : hash_password() → server_passwd_hash[65]
```

### 5-2. OpenSSL TLS 소켓 암호화

**모든 소켓 통신이 TLS 1.2+ 로 암호화됩니다.**

#### 인증서 구조

```
/etc/renux/
├── server.crt  ← server_e가 로드 (client_e가 검증)
├── server.key
├── master.crt  ← renux_master가 로드 (renux agent가 검증)
└── master.key
```

`setup.sh`에서 `openssl req -x509`로 자동 생성 (RSA 2048, 2년 유효).

#### 적용 범위

```
client_e ──TLS 1.2+ (인증서 검증)──► server_e       (port 8080)
renux    ──TLS 1.2+ (인증서 검증)──► renux_master   (port 9000)
```

#### `ssl_utils.h` API

```c
SSL_CTX *create_server_ssl_ctx(const char *cert, const char *key);
SSL_CTX *create_client_ssl_ctx(void);                          // SSL_VERIFY_NONE
SSL_CTX *create_client_ssl_ctx_verified(const char *ca_cert); // SSL_VERIFY_PEER (V2.1)
```

#### 각 바이너리 변경

| 바이너리 | TLS 역할 | 인증서 검증 |
|---|---|---|
| `server_e` | 서버 (SSL_accept) | 서버 측 — 인증서 제시 |
| `client_e` | 클라이언트 (SSL_connect) | `/etc/renux/server.crt` 로 검증 (V2.1) |
| `renux` | 클라이언트 (SSL_connect) | `/etc/renux/master.crt` 로 검증 (V2.1) |
| `renux_master` | 서버 (SSL_accept) | 서버 측 — 인증서 제시 |

### 5-3. `setup.sh` 개선

```
[1/6] 의존성 설치   — apt/yum/dnf 자동 감지 (libssl-dev, libcap-dev, libncurses-dev)
[2/6] 빌드          — make all (renux_master 포함)
[3/6] TLS 인증서    — /etc/renux/*.crt / *.key 자동 생성 (기존 파일 유지)
[4/6] 바이너리 설치 — server_e, client_e, renux, renux_master
[5/6] Agent 설정    — /etc/renux.conf (MASTER_IP, MASTER_PORT)
[6/6] systemd 등록  — renux.service + renux-master.service
```

---

## 6. V2.1 — 보안 검토 반영 수정 (2026-03-04)

### 6-1. Signal Handler Race Condition 수정 (`monitoring/monitor.cpp`)

**버그:** `signal_handler()`가 `net_mutex` 없이 `master_ssl`을 해제하여 Use-After-Free 및 async-signal-unsafe 함수 호출이 발생했습니다.

```c
// V2.0 (버그)
void signal_handler(int sig) {
    keep_running = 0;
    SSL_shutdown(master_ssl); SSL_free(master_ssl);  // ← Use-After-Free 위험
    SSL_CTX_free(g_ssl_ctx);                         // ← async-signal-unsafe
}

// V2.1 (수정)
void signal_handler(int sig) {
    keep_running = 0;
    // SSL 정리는 main() 루프 종료 후 기존 cleanup 코드에서 수행
}
```

**원인:** `send_log_to_master()`는 `net_mutex`로 `master_ssl`을 보호하지만, signal handler는 mutex 없이 동일 객체를 해제합니다. SIGTERM이 `SSL_write()` 실행 중에 도달하면 Use-After-Free가 발생합니다.

### 6-2. mTLS 서버 인증서 검증 적용

**변경:** `SSL_VERIFY_NONE` → `SSL_VERIFY_PEER` (CA 인증서로 서버 검증)

```c
// 신규 함수 (utils/ssl_utils.c)
SSL_CTX *create_client_ssl_ctx_verified(const char *ca_cert_path) {
    // SSL_CTX_load_verify_locations() + SSL_VERIFY_PEER
}
```

| 클라이언트 | V2.0 | V2.1 |
|---|---|---|
| `client_e` | `SSL_VERIFY_NONE` | `/etc/renux/server.crt` 검증 |
| `renux` 에이전트 | `SSL_VERIFY_NONE` | `/etc/renux/master.crt` 검증 |

**효과:** MITM(중간자 공격) 방어. 위조 서버에 에이전트가 연결되는 시나리오를 차단합니다.

### 6-3. Makefile macOS OpenSSL 경로 자동 감지

macOS에서 Homebrew로 설치된 OpenSSL 경로를 빌드 시 자동으로 포함합니다.

```makefile
OPENSSL_PREFIX  := $(shell brew --prefix openssl 2>/dev/null)
OPENSSL_CFLAGS  := $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include,)
OPENSSL_LDFLAGS := $(if $(OPENSSL_PREFIX),-L$(OPENSSL_PREFIX)/lib,)
```

---

## 7. 변경 파일 목록

### V2.0 (2026-03-03)

| 파일 | 상태 | 내용 |
|---|---|---|
| `utils/exec_utils.h` | 신규 | `exec_command` / `exec_command_buf` 선언 |
| `utils/exec_utils.c` | 신규 | `pipe/fork/execve` 래퍼 구현 |
| `utils/ssl_utils.h` | 수정 | SHA-256 + TLS 함수 선언, `extern "C"` 가드 |
| `utils/ssl_utils.c` | 수정 | SHA-256 (`EVP_sha256`) + `SSL_CTX` 생성 구현 |
| `server/service.h` | 수정 | `handle_client_request(SSL *ssl, ...)` 시그니처 변경 |
| `server/service.c` | 수정 | `popen()` 전면 제거, 입력 검증, `SSL_write` |
| `server/server.c` | 수정 | `SSL_CTX` 생성, `SSL_accept`, libcap, SHA-256 |
| `client/client.c` | 수정 | `SSL_connect`, `SSL_read/write`, `g_ssl` 전역 |
| `monitoring/monitor.cpp` | 수정 | TLS 전송, 역쉘 탐지, 웹쉘 탐지, 오프라인 버퍼 |
| `monitoring/master.cpp` | 수정 | `SSL_CTX` 로드, `SSL_accept`, `SSL_read` |
| `Makefile` | 수정 | 보안 플래그, `renux_master` all 포함, `-lssl -lcrypto` |
| `setup.sh` | 수정 | 의존성 설치, 인증서 생성, master 서비스 등록 |

### V2.1 (2026-03-04)

| 파일 | 상태 | 내용 |
|---|---|---|
| `monitoring/monitor.cpp` | 수정 | signal handler race condition 수정, mTLS 검증 적용 |
| `utils/ssl_utils.h` | 수정 | `create_client_ssl_ctx_verified()` 선언 추가 |
| `utils/ssl_utils.c` | 수정 | `create_client_ssl_ctx_verified()` 구현 |
| `client/client.c` | 수정 | `SSL_VERIFY_NONE` → `SSL_VERIFY_PEER` |
| `Makefile` | 수정 | macOS Homebrew OpenSSL 경로 자동 감지 |

---

## 8. 빌드 및 설치

```bash
# 전체 자동 설치 (권장)
sudo ./setup.sh

# 수동 빌드만
make clean && make all

# 생성되는 바이너리
./server_e        # 관리 서버  (port 8080, TLS)
./client_e        # 관리 클라이언트
./renux           # 모니터링 에이전트 (daemon, Linux 전용)
./renux_master    # 로그 집계 서버 (port 9000, TLS, Linux 전용)
```

### 의존성

```
libssl-dev     — TLS 암호화 (OpenSSL)
libcap-dev     — Privilege Drop (Linux)
libncurses-dev — TUI
```

---

## 9. 잔여 개선 과제

| 항목 | 우선순위 | 설명 |
|---|---|---|
| bcrypt/Argon2 비밀번호 해싱 | 중 | SHA-256 → bcrypt/argon2로 교체하면 brute-force 지연 효과 |
| IPv6 리버스쉘 탐지 | 낮 | 현재 `/proc/net/tcp` (IPv4)만 파싱. `/proc/net/tcp6` 추가 가능 |
| 탐지 이벤트 중앙 알림 | 낮 | ALERT 로그를 master에서 email/webhook으로 forwarding |
| eBPF 탐지 | 장기 | 30초 폴링 갭 해소. 커널 5.8+ / libbpf 필요 |
