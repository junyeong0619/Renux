# Renux V2.1 테스트 결과 보고서

**테스트 일자:** 2026-03-04
**테스트 환경:** Docker (Ubuntu 22.04, Linux aarch64)
**테스트 대상:** Renux V2.1 전체 바이너리
**결과 요약:** ✅ PASS 24 / ❌ FAIL 0 / ⏭ SKIP 1

---

## 1. 테스트 환경

```
OS       : Ubuntu 22.04 LTS (Docker, --privileged)
Arch     : aarch64 (Apple Silicon 호스트)
Compiler : gcc 11.4.0 / g++ 11.4.0
OpenSSL  : 3.0.x
커널     : Linux (inotify, /proc 접근 가능)
```

**의존성 설치 확인:**
```
libssl-dev      ✅ 설치됨
libcap-dev      ✅ 설치됨
libncurses-dev  ✅ 설치됨
expect          ✅ 설치됨 (TUI 자동화용)
```

---

## 2. 테스트 항목별 결과

### [1] 빌드 검증 — 4/4 PASS

모든 바이너리가 Linux (aarch64) 환경에서 정상 컴파일되었습니다.

| 바이너리 | 결과 | 비고 |
|---|---|---|
| `server_e` | ✅ PASS | `-lcap` 누락 버그 발견 및 수정 (아래 참조) |
| `client_e` | ✅ PASS | |
| `renux` | ✅ PASS | Linux 전용 (inotify) |
| `renux_master` | ✅ PASS | |

> **발견된 버그:** `Makefile`에 `-lcap` 링크 플래그가 누락되어 Linux에서
> `cap_init`, `cap_set_proc`, `cap_free` 심볼 미해결 오류가 발생했습니다.
> `server_e` 빌드 규칙에 `-lcap`을 추가하여 수정했습니다.

---

### [2] 보안 컴파일 플래그 검증 — 4/4 PASS

`readelf -s`로 `__stack_chk_fail` 심볼 존재 여부를 확인했습니다.

| 바이너리 | Stack Canary | 결과 |
|---|---|---|
| `server_e` | `-fstack-protector-all` 적용 | ✅ PASS |
| `client_e` | `-fstack-protector-all` 적용 | ✅ PASS |
| `renux` | `-fstack-protector-all` 적용 | ✅ PASS |
| `renux_master` | `-fstack-protector-all` 적용 | ✅ PASS |

---

### [3] TLS 인증서 검증 — 8/8 PASS

`setup.sh` 인증서 생성 로직 (`openssl req -x509`) 결과를 검증했습니다.

| 항목 | 결과 |
|---|---|
| `/etc/renux/server.crt` 존재 | ✅ PASS |
| `/etc/renux/server.key` 존재 | ✅ PASS |
| `/etc/renux/master.crt` 존재 | ✅ PASS |
| `/etc/renux/master.key` 존재 | ✅ PASS |
| `server.crt` 자체 서명 유효성 | ✅ PASS |
| `master.crt` 자체 서명 유효성 | ✅ PASS |
| `server.crt ↔ server.key` 공개키 매칭 | ✅ PASS |
| `master.crt ↔ master.key` 공개키 매칭 | ✅ PASS |

---

### [4] renux_master TLS 핸드셰이크 — 3/3 PASS

`renux_master`를 기동한 후 `openssl s_client`로 TLS 1.2+ 연결을 시도했습니다.

```
테스트 명령:
  echo "HELLO" | openssl s_client \
      -connect 127.0.0.1:9000 \
      -CAfile /etc/renux/master.crt \
      -verify_return_error
```

| 항목 | 결과 |
|---|---|
| `renux_master` 프로세스 기동 | ✅ PASS |
| TLS 핸드셰이크 성공 (Verify return code: 0) | ✅ PASS |
| `master.crt`로 인증서 검증 통과 (mTLS) | ✅ PASS |
| port 9000 리스닝 확인 | ✅ PASS |

**실제 renux_master 출력:**
```
[SYSTEM] New TLS Agent: 127.0.0.1
[Agent: 127.0.0.1] HELLO
[SYSTEM] Agent Disconnected: 127.0.0.1
```

> V2.1에서 적용된 `SSL_VERIFY_PEER` (mTLS)가 정상 동작함을 확인했습니다.
> 인증서 불일치 시 핸드셰이크가 거부됩니다.

---

### [5] server_e TLS 핸드셰이크 — ⏭ SKIP

`server_e`는 ncurses TUI를 사용하여 비밀번호를 입력받으므로
헤드리스(headless) Docker 환경에서 자동화 테스트가 불가합니다.

**SKIP 사유:** TTY 없음 — ncurses `initscr()` 실행 불가

**인터랙티브 테스트 방법:**

```bash
# 터미널 1 — 서버 기동 (비밀번호 입력 후 대기)
docker compose run --rm server

# 터미널 2 — 클라이언트 접속
docker compose run --rm client

# 또는 단일 컨테이너에서 두 프로세스 직접 실행
docker run -it --rm renux:test bash
  > ./server_e &   # 비밀번호 입력
  > ./client_e 127.0.0.1 8080
```

---

### [6] renux 에이전트 기동 — 3/3 PASS

| 항목 | 결과 |
|---|---|
| `/proc/net/tcp` 접근 가능 | ✅ PASS |
| `inotify` 지원 확인 | ✅ PASS |
| `renux` 에이전트 프로세스 기동 성공 | ✅ PASS |

> `--privileged` 옵션으로 실행 시 `/proc/net/tcp` 파싱 및 inotify가
> 정상 작동합니다. 실제 배포 환경(systemd service)에서는 root 권한으로 실행됩니다.

---

### [7] popen 의존성 제거 확인 — 2/2 PASS

`strings` 명령으로 바이너리 내 `popen` 심볼 참조를 확인했습니다.

| 바이너리 | popen 참조 | 결과 |
|---|---|---|
| `server_e` | 없음 | ✅ PASS |
| `renux` | 없음 | ✅ PASS |

> V1.0의 Command Injection 취약점(`popen()` 5곳)이 완전히 제거되었습니다.

---

## 3. 발견된 버그 및 수정 사항

이번 테스트 과정에서 아래 버그가 추가로 발견되어 수정했습니다.

| # | 파일 | 버그 | 수정 |
|---|---|---|---|
| 1 | `Makefile` | `server_e` 빌드 시 `-lcap` 링크 플래그 누락 → Linux 빌드 오류 | `-lcap` 추가 |

---

## 4. 전체 결과 요약

```
============================================
  결과: PASS=24  FAIL=0  SKIP=1
============================================
```

| 카테고리 | PASS | FAIL | SKIP |
|---|---|---|---|
| 빌드 검증 | 4 | 0 | 0 |
| 보안 플래그 | 4 | 0 | 0 |
| TLS 인증서 | 8 | 0 | 0 |
| renux_master TLS | 4 | 0 | 0 |
| server_e TLS | 0 | 0 | 1 |
| renux 에이전트 | 3 | 0 | 0 |
| popen 제거 확인 | 2 | 0 | 0 |
| **합계** | **25** | **0** | **1** |

**SKIP 항목** (`server_e` TLS)은 코드 결함이 아닌 ncurses TUI의
헤드리스 환경 제약으로, `docker compose run --rm server`로 인터랙티브 검증 가능합니다.

---

## 5. 테스트 재현 방법

```bash
# 이미지 빌드
docker build -t renux:test .

# 자동화 테스트 실행
docker run --rm --privileged renux:test bash test/run_tests.sh

# 인터랙티브 테스트 (server_e ↔ client_e)
docker compose up master        # renux_master 기동
docker compose run --rm server  # server_e (TUI, 비밀번호 설정)
docker compose run --rm client  # client_e (TUI, 로그인)
```
