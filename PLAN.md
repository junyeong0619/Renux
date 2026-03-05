# Renux V2.0 개발 계획서

**작성일:** 2026-03-03
**현재 버전:** V1.0 (프로토타입)
**목표 버전:** V2.0 (보안 플랫폼)

---

## 현재 코드 상태 분석 (V1.0 진단)

### 확인된 주요 취약점

| 파일 | 문제 | 위치 |
|---|---|---|
| `service.c` | `popen()` + 미검증 입력 → Command Injection | L100, L179, L196, L212, L238 |
| `service.c` | `trace` 명령: `target_user` 그대로 쉘에 전달 | L98-L100 |
| `service.c` | `set_quota`: 5개 파라미터 모두 무검증 | L212 |
| `monitor.cpp` | `popen("diff -u ...")` 내부에서도 사용 | L222 |
| `ssl_utils.c` | 이름만 ssl_utils, 실제로는 **djb2 해시** 함수만 존재 (암호학적으로 취약) | L7-L15 |
| `server.c` | 비밀번호를 djb2 해시로 검증 → 충돌 가능성 존재 | L128, L280 |
| `Makefile` | 보안 컴파일 플래그 전무, `renux_master`가 `all` 타겟에서 누락 | L4-L5, L7 |
| `monitor.cpp` | 네트워크 단절 시 로그 유실 (재연결만 하고 버퍼링 없음) | L129-L131 |

### 아키텍처 흐름 이해 (변경 시 주의사항)

**`trace` 명령 체인 (가장 위험한 경로):**
```
client → send("trace <user>") → server_e → popen("/usr/bin/renux trace <user>") → renux 바이너리
```
`<user>` 값이 client → server_e → shell → renux 로 세 단계를 거쳐 전달되므로
인젝션 payload가 그대로 쉘에 도달함.

**`END_OF_LIST` 프로토콜:**
`getu`, `get_proc`, `get_quota`, `set_quota`, `get_fstab_quota_list` 명령은
마지막에 `"END_OF_LIST\n"` 센티넬을 전송하여 클라이언트 수신 스레드가 누적을 종료함.
`service.c` 수정 시 이 센티넬을 반드시 유지해야 클라이언트 모드 플래그가 정상 해제됨.

---

## Phase 1 — Secure Coding (최우선, 2주)

### 목표: Command Injection 원천 차단

#### 1-1. `execve()` 래퍼 함수 구현 (`utils/exec_utils.c` 신규)

**대상 코드 (`service.c`):**

```c
// 현재 (취약) — 쉘 경유
snprintf(command, sizeof(command), "/usr/bin/renux trace %s", target_user);
pipe = popen(command, "r");  // L98-L100

snprintf(command, sizeof(command), "ps -u %s", target_username);         // L179
snprintf(command, sizeof(command), "quota -u %s 2>&1", target_username); // L196
snprintf(command, sizeof(command), "setquota -u %s %s %s 0 0 %s", ...);  // L212
popen("awk -F: '{print $1}' /etc/passwd", "r");                          // L238
```

**구현할 래퍼 시그니처:**

```c
// utils/exec_utils.h
int exec_command(int output_fd, const char *path, char *const argv[]);
// pipe() + fork() + execve() 조합
// 쉘(/bin/sh)을 거치지 않으므로 메타문자 무효화
```

**service.c 교체 방향:**

```c
// 변경 후 (trace): 인자를 배열로 분리 → 쉘 경유 없음
char *args[] = {"/usr/bin/renux", "trace", target_user, NULL};
exec_command(client_socket, "/usr/bin/renux", args);

// 변경 후 (get_proc)
char *args[] = {"/bin/ps", "-u", target_username, NULL};
exec_command(client_socket, "/bin/ps", args);

// 변경 후 (getu): execve() 래퍼조차 불필요
// popen("awk -F: '{print $1}' /etc/passwd") → getpwent() API로 완전 대체
// send_etc_passwd() 함수가 이미 getpwent() 사용 중 — 동일 패턴 적용
while ((user_info = getpwent()) != NULL) {
    send(client_socket, user_info->pw_name, strlen(user_info->pw_name), 0);
    send(client_socket, "\n", 1, 0);
}
send(client_socket, "END_OF_LIST\n", 12, 0);  // 센티넬 유지 필수
```

#### 1-2. 입력값 화이트리스트 검증

**대상:** `handle_client_request()` 진입 시점

```c
// service.c 상단에 추가할 검증 함수
static int is_valid_username(const char *input) {
    // POSIX username: [a-z_][a-z0-9_-]{0,31}
    // 특수문자(; | & ` > < $ \) 포함 시 즉시 거부
}

static int is_valid_number(const char *input) {
    // quota 값: 순수 숫자만 허용
}
```

**검증 적용 위치:**
- `trace` 명령: `target_user` 검증 (L92 이후)
- `getinfo / get_proc / get_quota`: `target_username` 검증 (L154 이후)
- `set_quota`: `soft_limit`, `hard_limit`, `filesystem` 각각 검증 (L206 이후)

#### 1-3. `monitor.cpp` diff 함수 개선

**현재 (`monitor.cpp` L222):**

```cpp
std::string cmd = "diff -u -N " + temp_path + " " + filepath + " 2>&1";
FILE* pipe = popen(cmd.c_str(), "r");  // filepath에 경로 인젝션 가능
```

**대안:** `execve()`로 교체하거나, 파일 내용을 직접 라인 단위 비교로 구현 (외부 프로세스 불필요)

---

## Phase 2 — System Hardening (1주)

### 2-1. 컴파일 보안 옵션 (`Makefile`)

**현재:**

```makefile
CFLAGS   = -g -Wall -std=gnu99 -D_XOPEN_SOURCE=700   # L4: 보안 플래그 없음
CXXFLAGS = -std=c++17                                  # L5: 동일
# renux_master가 all 타겟에 누락                       # L7
```

**변경:**

```makefile
CFLAGS   = -Wall -O2 -std=gnu99 -D_XOPEN_SOURCE=700 \
           -fstack-protector-all -D_FORTIFY_SOURCE=2 \
           -Wformat -Wformat-security

CXXFLAGS = -std=c++17 -O2 \
           -fstack-protector-all -D_FORTIFY_SOURCE=2

LDFLAGS  = -Wl,-z,relro,-z,now

# all 타겟에 renux_master 추가
TARGETS = server_e client_e renux renux_master
```

> `-g` (디버그 심볼)는 릴리즈 빌드에서 제거

### 2-2. 권한 최소화 (libcap)

**현재 문제:** `server_e` / `renux`가 root 권한으로 실행

**구현 위치:** `server/server.c` 초기화 직후 (kqueue/epoll 등록 완료 후)

```c
#include <sys/capability.h>
#include <sys/prctl.h>

// 주의: server.c는 #ifdef __APPLE__ / #elif __linux__ 블록으로 분기됨
// libcap은 Linux 전용이므로 반드시 #elif __linux__ 블록 안에 위치시킬 것

// server_e에서 필요한 capability:
// - CAP_SETUID / CAP_SETGID: 없음 (포트 8080은 1024 이상이므로 CAP_NET_BIND_SERVICE 불필요)
// - getpwnam/getpwent: 일반 파일 읽기로 처리 가능
// → 사실상 root capability 전부 드롭 가능

// renux에서 필요한 capability:
// - CAP_DAC_READ_SEARCH: /root, /home 감시용 inotify
// - 나머지 전부 드롭
```

---

## Phase 3 — Intelligent Monitoring (3주)

### 3-1. 리버스 쉘 탐지 (`monitor.cpp` 신규 스레드)

**구현 방식:** `/proc/net/tcp` 주기적 파싱

```cpp
void detect_reverse_shell() {
    // 1. /proc/net/tcp 파싱 → 외부 연결 소켓 추출 (ESTABLISHED 상태)
    // 2. 각 소켓의 inode로 /proc/[PID]/fd/ 역추적 → 소유 프로세스 특정
    // 3. 프로세스명이 bash/sh/nc/python 등이면 경보
    //    → write_agent_log()로 마스터에 즉시 전송
}
// 별도 std::thread로 30초마다 실행 (inotify 루프와 독립)
```

### 3-2. 프로세스 트리 분석

```cpp
// 웹서버 → 쉘 생성 패턴 감지 (웹쉘 의심)
// /proc/[PID]/stat 에서 PPID 추출
// PPID의 comm이 httpd/nginx/apache2 이고 자신이 sh/bash → 경보
void check_webshell_pattern() { ... }
// detect_reverse_shell()과 같은 주기 스레드에서 함께 실행
```

### 3-3. 네트워크 단절 대응 (로그 버퍼링)

**현재 (`monitor.cpp` L129-L131):**

```cpp
if (master_sock == -1) connect_to_master();
if (master_sock == -1) return; // ← 연결 실패 시 로그 유실
```

**개선:** STL queue로 로컬 버퍼링

```cpp
std::queue<std::string> offline_log_buffer;  // 전역 추가
const size_t MAX_BUFFER = 1000;              // 최대 1000건

// send_log_to_master() 내부:
// - 연결 실패 시 buffer에 push (MAX_BUFFER 초과 시 오래된 것 pop)
// - 재연결 성공 시 buffer 전체 flush 후 정상 전송
// 주의: std::queue 접근은 mutex로 보호 (inotify 루프 + 탐지 스레드가 동시 호출)
```

---

## Phase 4 — Infrastructure (2주)

### 4-1. 비밀번호 해싱 교체 (`ssl_utils.c` 재구현)

**현재 문제:** `hash_string()`은 djb2 변형 — 해시 충돌 가능, 무차별 대입 공격에 취약

**영향 범위:**
- `server.c` L128: 서버 시작 시 관리자 비밀번호 해싱
- `server.c` L280: 클라이언트 로그인 검증 (`is_valid_login()`)
- `service.c`: `is_valid_login()` 호출부

**교체 방향:**
```c
// ssl_utils.h 기존 hash_string() 대체
// 옵션 A: SHA-256 (OpenSSL EVP API)
// 옵션 B: bcrypt (libcrypt) — brute-force 지연 효과 있음
int hash_password(const char *plain, char *out_hash, size_t out_len);
int verify_password(const char *plain, const char *stored_hash);
```

### 4-2. 통신 암호화 (OpenSSL TLS)

**현재:** 모든 소켓 통신이 평문 TCP

**구현할 함수 (`ssl_utils.h`에 추가):**

```c
SSL_CTX* create_server_ssl_ctx(const char *cert, const char *key);
SSL_CTX* create_client_ssl_ctx(void);
int ssl_send(SSL *ssl, const char *data, size_t len);
int ssl_recv(SSL *ssl, char *buf, size_t len);
```

**적용 범위:**
- `master.cpp`: `accept()` 후 SSL handshake
- `monitor.cpp`: `connect_to_master()` 후 SSL wrap — `LOG|IP|msg\n` 패킷 포맷 유지
- `server.c` ↔ `client.c`: 기존 소켓에 동일 적용

**Makefile 수정:**

```makefile
server_e: ...
    $(CC) $(CFLAGS) $(LDFLAGS) ... -lncurses -lssl -lcrypto

client_e: ...
    $(CC) $(CFLAGS) $(LDFLAGS) ... -lncurses -lpthread -lssl -lcrypto

renux renux_master: ...
    $(CXX) $(CXXFLAGS) $(LDFLAGS) ... -lssl -lcrypto
```

### 4-3. `setup.sh` 개선

**현재 문제:**
- 의존성 사전 설치 없음
- `make`만 실행 → `renux_master`가 `all` 타겟 누락 상태이므로 빌드 안 됨 (4-1에서 Makefile 수정 후 해결)
- master용 systemd 서비스 파일 없음

**추가할 내용:**

```bash
# 의존성 자동 설치
apt-get install -y libssl-dev libcap-dev libncurses-dev 2>/dev/null || \
yum install -y openssl-devel libcap-devel ncurses-devel 2>/dev/null

# master 바이너리 설치
sudo cp renux_master /usr/local/bin/renux_master

# master용 서비스 파일 생성 (agent와 별도)
sudo tee /etc/systemd/system/renux-master.service > /dev/null <<EOF
[Unit]
Description=Renux Master Server
After=network.target
[Service]
ExecStart=/usr/local/bin/renux_master
Restart=always
[Install]
WantedBy=multi-user.target
EOF
```

---

## 개발 일정 요약

```
Week 1-2  │ Phase 1: Secure Coding
           │  - exec_utils 래퍼 구현 (pipe/fork/execve)
           │  - service.c 전면 교체 (END_OF_LIST 센티넬 유지)
           │  - getu → getpwent() 직접 호출로 대체
           │  - 입력 검증 로직 (화이트리스트)
           │
Week 3     │ Phase 2: Hardening
           │  - Makefile 보안 플래그 + renux_master를 all에 추가
           │  - libcap 적용 (#elif __linux__ 블록 한정)
           │
Week 4-6   │ Phase 3: Monitoring 고도화
           │  - 리버스쉘 탐지 스레드 (/proc/net/tcp)
           │  - 프로세스 트리 분석 (웹쉘 패턴)
           │  - 오프라인 로그 버퍼링 (mutex 보호 queue)
           │
Week 7-8   │ Phase 4: Infrastructure
           │  - hash_string() → SHA-256/bcrypt 교체
           │  - OpenSSL TLS 적용 (전 통신 경로)
           │  - setup.sh 개선
```

---

## 파일별 작업 범위 요약

| 파일 | 작업 | 우선순위 |
|---|---|---|
| `server/service.c` | `popen()` → `execve()` 래퍼 교체, `getu` → `getpwent()`, 입력 검증, `END_OF_LIST` 센티넬 유지 | **P0** |
| `utils/exec_utils.c` (신규) | `pipe/fork/execve` 래퍼 함수 구현 | **P0** |
| `Makefile` | 보안 컴파일 플래그 추가, `renux_master`를 `all` 타겟에 포함 | **P1** |
| `server/server.c` | libcap 권한 드롭 (`#elif __linux__` 블록 한정) | **P1** |
| `monitoring/monitor.cpp` | 역쉘 탐지 스레드, 프로세스 트리 분석, mutex 보호 로그 버퍼링 | **P2** |
| `utils/ssl_utils.c` | `hash_string()` → SHA-256/bcrypt 교체 + OpenSSL TLS 함수 구현 | **P3** |
| `setup.sh` | 의존성 자동 설치, `renux_master` 서비스 파일 등록 | **P3** |
