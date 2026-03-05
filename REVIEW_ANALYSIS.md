# Renux V2.0 기술 검토 분석 보고서

**작성일:** 2026-03-04
**대상:** 3자 기술 검토 권고사항 (eBPF, Rust, mTLS/bcrypt) + 코드 버그 발견

---

## 개요

V2.0 구현 이후 외부 기술 검토에서 세 가지 개선 방향이 제안되었습니다.
각 항목의 실현 가능성과 우선순위를 V2.0 구현 기준으로 분석합니다.
추가로, 검토 과정에서 `monitor.cpp`에서 실제 버그가 발견되었습니다.

---

## 1. eBPF 탐지 — 타당하지만 장기 과제

### 현재 방식의 한계 (30초 폴링)

```
T=0s   reverse shell 실행
T=29s  detect_reverse_shell() 실행 → 탐지
       (최대 29초 동안 탐지 불가)
```

30초 창 동안 공격자가 행동을 완료할 수 있다는 지적은 타당합니다.

### eBPF가 해결하는 것

- `execve()` syscall에 직접 훅 → fork/exec 시 즉시 캡처 (폴링 완전 제거)
- 커널 레벨에서 프로세스 계보 추적 → 탐지 정확도 향상
- `/proc` 폴링 대비 오버헤드 최소화

### 실현 가능성 문제

| 제약 | 내용 |
|---|---|
| 커널 버전 | BPF 기본: 4.18+, BTF/CO-RE: 5.8+ |
| 빌드 체계 | libbpf + BPF C 코드 → 기존 Makefile과 별도 |
| 개발 난이도 | 현재 프로젝트 전체 복잡도보다 높음 |
| 배포 | 대상 호스트의 커널 버전 보장 필요 |

### 결론

이론적으로 정확한 방향이나 단기 구현 대상이 아닙니다.
현재 `/proc/net/tcp` 방식으로 탐지는 가능하므로, eBPF는 장기 로드맵 항목으로 분류합니다.

---

## 2. Rust 마이그레이션 — 효용 대비 비용 불균형

### 핵심 전제 재검토

Rust 마이그레이션의 근거는 C의 메모리 안전성 취약점입니다.
그러나 이 프로젝트의 주요 취약점(`popen()` Command Injection)은
**V2.0에서 `execve()` 래퍼로 이미 완전히 해결**되었습니다.

### 마이그레이션 비용 추산

| 항목 | 비고 |
|---|---|
| 12개 파일 전면 재작성 | C → Rust는 직접 포팅 불가 |
| ncurses TUI | `pancurses`/`cursive` 크레이트 학습 필요 |
| OpenSSL 바인딩 | `openssl` 크레이트 (API 차이 존재) |
| inotify | `inotify` 크레이트 |
| kqueue (macOS 지원) | Rust 에코시스템 지원 미흡 |
| epoll/kqueue 이벤트 루프 | `tokio` 또는 직접 구현 |

현재 코드에 명시적 UB(Undefined Behavior)는 없으며,
남아 있는 위협 모델에 Rust가 추가로 제공하는 실질적 보안 효과가 미미합니다.

### 결론

원론적으로 옳은 방향이지만, 이 프로젝트의 실제 위협 모델 대비 과잉 대응입니다.
마이그레이션 비용 대비 편익이 현저히 낮아 **현 단계에서는 불필요**합니다.

---

## 3. mTLS + bcrypt — 가장 실현 가능한 즉각 개선

### mTLS (클라이언트 인증서 검증)

**현재 상태** (`utils/ssl_utils.c`):

```c
// create_client_ssl_ctx() 내부
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  // 서버 인증서 검증 없음
```

`SSL_VERIFY_NONE`이므로 중간자(MITM) 공격에 노출됩니다.

**변경 방법:**

```c
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
SSL_CTX_load_verify_locations(ctx, "/etc/renux/master.crt", NULL);
```

- 코드 변경: 2-3줄
- 추가 필요: CA 인증서를 모든 에이전트 호스트에 배포하는 절차 수립
- 기존 구조 변경 없음

**결론**: 코드 변경 최소, 보안 효과 높음. 가장 즉각 적용 가능한 항목입니다.

### bcrypt / Argon2 비밀번호 해싱

**현재 상태** (`utils/ssl_utils.c`):

```c
// SHA-256 단순 해시 — 반복(iteration) 없음
EVP_DigestUpdate(ctx, plain, strlen(plain));
// → GPU 브루트포스에 취약 (초당 수십억 해시 가능)
```

**권장 교체:**

| 알고리즘 | 장점 | 단점 |
|---|---|---|
| bcrypt | 검증된 구현체, 라이브러리 풍부 | 메모리 경도 없음 |
| Argon2 | 최신 표준, 메모리+시간 경도 | 라이브러리 별도 설치 |

둘 다 SHA-256 대비 브루트포스 저항성이 수백만 배 이상 높습니다.
`libcrypt`(bcrypt) 또는 별도 헤더-온리 라이브러리로 교체 가능합니다.

**결론**: 단기 적용 권장.

---

## 4. Signal Handler Race Condition — 발견된 실제 버그

> **검토 중 `monitoring/monitor.cpp`에서 실제 버그를 발견했습니다.**

### 문제 위치

**`monitoring/monitor.cpp:396-401`**

```cpp
void signal_handler(int sig) {
    keep_running = 0;
    // ↓ 위험: net_mutex 없이 master_ssl 해제
    if (master_ssl) { SSL_shutdown(master_ssl); SSL_free(master_ssl); master_ssl = nullptr; }
    if (g_ssl_ctx)  { SSL_CTX_free(g_ssl_ctx);  g_ssl_ctx = nullptr; }
    if (master_sock != -1) { close(master_sock); master_sock = -1; }
}
```

### 문제 1 — Use-After-Free (Race Condition)

```
inotify 메인 루프 또는 detection_loop 스레드:
  write_agent_log()
    → send_log_to_master()
      → net_mutex.lock()    ← mutex 획득
      → SSL_write(master_ssl, ...)    ← master_ssl 사용 중

동시에 SIGTERM 도달 → signal_handler() 실행:
  SSL_free(master_ssl)    ← net_mutex 없이 호출!
  ↑ 사용 중인 객체를 해제 → Use-After-Free → Segfault 또는 메모리 오염
```

`send_log_to_master()`는 `net_mutex`로 `master_ssl` 접근을 보호하지만,
signal handler는 mutex를 전혀 획득하지 않고 동일 객체를 해제합니다.

### 문제 2 — Async-Signal-Unsafe 함수 호출

POSIX는 signal handler에서 호출 가능한 함수 목록을 엄격히 제한합니다.
`SSL_shutdown()`, `SSL_free()`, `SSL_CTX_free()`는 내부적으로 mutex/heap 조작을 수행하므로
signal handler 내에서의 호출이 **POSIX 표준 위반**입니다.

### 올바른 해결 방향

Signal handler에서는 `keep_running = 0` 설정만 수행합니다.
이미 `main()` 646-648줄에 cleanup 코드가 존재하므로, 루프 종료 후 자동으로 실행됩니다:

```cpp
// main() 종료 직전 — 이미 올바른 위치에 존재
if (master_ssl)  { SSL_shutdown(master_ssl); SSL_free(master_ssl); }
if (g_ssl_ctx)   { SSL_CTX_free(g_ssl_ctx); }
if (master_sock != -1) close(master_sock);
```

**signal_handler 내 SSL 해제 코드 3줄이 불필요하고 위험합니다.**

---

## 5. 우선순위 종합

| 순위 | 항목 | 분류 | 이유 |
|---|---|---|---|
| **즉시** | Signal handler race condition 수정 | 버그 | Use-After-Free + async-signal-unsafe |
| **단기** | mTLS (SSL_VERIFY_PEER) 적용 | 보안 | 코드 2-3줄, MITM 방어 |
| **단기** | bcrypt/Argon2 비밀번호 해싱 | 보안 | SHA-256 단순 해시 교체 |
| **장기** | eBPF 탐지 도입 | 기능 | 폴링 갭 해소, 구현 복잡도 높음 |
| **불필요** | Rust 마이그레이션 | — | 주요 취약점 이미 해결됨 |

---

## 부록 — /proc 파싱 기술적 정확성 검토

검토 과정에서 `/proc` 파싱 구현도 확인했습니다.

**`get_proc_ppid()` (`monitor.cpp:228-241`):**

```cpp
// /proc/[pid]/stat 파싱
// stat 형식: "pid (comm) state ppid ..."
// comm 필드는 공백/괄호 포함 가능 → rfind(')') 로 안전하게 처리
size_t rp = line.rfind(')');
std::istringstream iss(line.substr(rp + 2));
std::string state, ppid;
iss >> state >> ppid;
```

`rfind(')')`을 사용하여 프로세스 이름에 `)`가 포함된 경우에도 올바르게 동작합니다.
이 구현은 기술적으로 정확합니다.
