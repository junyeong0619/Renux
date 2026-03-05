# eBPF 기술 보고서 — Renux V3.0 적용 기준

작성일: 2026-03-05

---

## 1. eBPF 개요

eBPF(extended Berkeley Packet Filter)는 커널 소스코드를 수정하거나 커널 모듈을 로드하지 않고 **커널 공간에서 샌드박스 프로그램을 실행**하는 리눅스 커널 기술이다.

### 기존 방식 vs eBPF

| 항목 | 기존 (Renux V2) | eBPF (Renux V3) |
|------|----------------|-----------------|
| 쉘 명령 탐지 | `.bashrc` 훅 주입 | `execve` tracepoint |
| TCP 연결 탐지 | `/proc/net/tcp` 30초 폴링 | `tcp_connect` kprobe (즉시) |
| 파일 접근 탐지 | inotify (`/root`, `/home` 한정) | `openat` tracepoint (전체 경로) |
| 우회 가능성 | bash `--norc`, `sh`, `zsh` 등 | **원천 차단** (syscall 진입점) |
| 감지 지연 | 최대 30초 | **0ms** (동기 이벤트) |

---

## 2. eBPF 실행 모델

```
사용자 공간                      커널 공간
───────────────────            ──────────────────────────────
                               ┌─────────────────┐
libbpf 로더                    │  BPF Verifier   │  ← 안전성 검증
(monitor.cpp)  ──── load ───▶  │  JIT Compiler   │  ← x86_64 네이티브 변환
                               └────────┬────────┘
                                        │ attach
                               ┌────────▼────────┐
                               │  Hook Points     │
                               │  - tracepoint    │
                               │  - kprobe        │
                               └────────┬────────┘
                                        │ event
                               ┌────────▼────────┐
                               │  BPF Maps        │  ← 커널-유저 공유 메모리
                               │  (Ring Buffer)   │
                               └────────┬────────┘
                                        │ read
monitor.cpp    ◀── poll ───────────────┘
(handle_event)
```

**핵심 보안 모델:**
- BPF Verifier가 루프, null 포인터, 범위 초과 등을 정적 분석으로 차단
- eBPF 프로그램은 커널 패닉을 유발할 수 없음
- CAP_BPF (또는 CAP_SYS_ADMIN) 권한 필요

---

## 3. Renux V3 사용 Hook 상세

### ① `tp/syscalls/sys_enter_execve` — 프로세스 실행 탐지

**SEC 선언:** `SEC("tp/syscalls/sys_enter_execve")`

모든 `execve()` 시스템 콜 진입점에서 실행된다. `argv[0]`(실행 파일 경로)를 캡처하고,
프로세스 이름이 SHELL_NAMES(`bash`, `sh`, `nc`, `python`...)에 해당하면 SHELL 태그를 추가한다.

**탐지 범위:**
- `bash --norc`로 `.bashrc` 훅 우회해도 탐지
- `sh -c "cmd"` 형태도 탐지
- python 인터프리터를 통한 쉘 실행 탐지

### ② `kprobe/tcp_connect` — TCP 연결 탐지 (즉시)

**SEC 선언:** `SEC("kprobe/tcp_connect")`

`tcp_connect()` 커널 함수 진입 시 실행된다. `sock` 구조체에서 목적지 IP/포트를 읽어
`127.0.0.1`, `0.0.0.0`이 아닌 외부 연결이고 comm이 SHELL_NAMES이면 REVERSE_SHELL ALERT를 발행한다.

**기존 방식과 차이:**
- 기존: ESTABLISHED 상태 30초마다 폴링 → 순간 연결 탐지 불가
- eBPF: connect() 호출 즉시 탐지 → 0ms 지연

### ③ `tp/syscalls/sys_enter_openat` — 파일 접근 탐지

**SEC 선언:** `SEC("tp/syscalls/sys_enter_openat")`

플래그에 `O_WRONLY | O_RDWR | O_CREAT`가 포함된 쓰기 목적 openat만 기록한다.
경로 필터: `/etc/`, `/root/`, `/home/`, `/tmp/` 접두사.

**기존 inotify 대비 추가 탐지:**
- `/tmp/evil.sh` 생성 (inotify 미감시 경로)
- `/etc/crontab`, `/etc/passwd` 수정
- 읽기 전용(O_RDONLY)은 제외 → 로그 폭주 방지

### ④ `tp/sched/sched_process_fork` — 프로세스 포크 탐지

**SEC 선언:** `SEC("tp/sched/sched_process_fork")`

웹쉘 탐지에 활용한다. 웹서버(`httpd`, `nginx`, `php-fpm`...)가 부모이고
자식 프로세스가 SHELL_NAMES이면 WEBSHELL 의심 알림을 발행한다.

---

## 4. BPF Ring Buffer

Ring Buffer는 커널 5.8에서 도입된 **고성능 이벤트 큐**다.

### Perf Event Array vs Ring Buffer

| 항목 | Perf Event Array | Ring Buffer |
|------|-----------------|-------------|
| 메모리 구조 | CPU당 별도 버퍼 | 단일 공유 버퍼 |
| 순서 보장 | 미보장 | **보장** |
| 메모리 효율 | 낮음 | 높음 |
| API 복잡도 | 복잡 | 단순 |
| 최소 커널 | 4.x | **5.8** |

### Renux 설정값

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);  // 256KB
} events SEC(".maps");
```

유저 공간 폴링:
```cpp
ring_buffer__poll(rb, 100 /* ms timeout */);
// 100ms 내 이벤트 있으면 즉시 handle_event 콜백 호출
// 없으면 100ms 대기 후 반환 (CPU busy-wait 없음)
```

---

## 5. CO-RE (Compile Once, Run Everywhere)

CO-RE는 **서로 다른 커널 버전에서 동일한 eBPF 바이너리가 동작**하게 하는 기술이다.

### 동작 원리

1. 커널이 BTF(BPF Type Format) 타입 정보를 `/sys/kernel/btf/vmlinux`에 노출
2. eBPF 컴파일 시 BTF 참조 정보 임베딩
3. 로드 시점에 libbpf가 현재 커널 BTF와 대조 → 구조체 오프셋 자동 보정

```c
// BPF_CORE_READ 매크로: 커널 버전 무관 오프셋 자동 보정
__u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
```

### 커널 버전 요구사항

| 기능 | 최소 커널 | Ubuntu 대응 |
|------|----------|------------|
| BPF_MAP_TYPE_RINGBUF | **5.8** | 20.10+ |
| CO-RE (BTF) | 5.2 | 20.04+ |
| kprobe/tcp_connect | 4.4 | 16.04+ |
| Ubuntu 22.04 기본 커널 | **5.15** | **✅ 모두 충족** |

---

## 6. libbpf Skeleton 빌드 과정

```
renux.bpf.c
    │
    ▼  clang -O2 -target bpf -D__TARGET_ARCH_x86_64
renux.bpf.o          ← BPF ELF 오브젝트
    │
    ▼  bpftool gen skeleton renux.bpf.o name renux
renux.skel.h         ← 자동 생성 C 헤더
    │                   (renux_bpf__open_and_load, __attach, __destroy 포함)
    ▼  g++ -I ebpf/ ... -lbpf -lelf -lz
renux                ← 최종 실행파일
```

**Skeleton API:**
```cpp
// 로드: ELF 파싱 → Verifier → JIT → 커널 적재
struct renux_bpf *skel = renux_bpf__open_and_load();

// Attach: SEC 선언 기반 자동 hook 연결
renux_bpf__attach(skel);

// Ring buffer 이벤트 루프
struct ring_buffer *rb = ring_buffer__new(
    bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);

while (keep_running)
    ring_buffer__poll(rb, 100);

// 정리
renux_bpf__destroy(skel);
```

---

## 7. 이벤트 구조체 (커널-유저 공유)

```c
// renux.bpf.c 와 monitor.cpp 에서 공통 사용
#define EVENT_EXEC    1
#define EVENT_CONNECT 2
#define EVENT_OPEN    3
#define EVENT_FORK    4

struct renux_event {
    __u8  type;           // 이벤트 종류
    __u32 pid;            // 발생 프로세스 PID
    __u32 ppid;           // 부모 PID (FORK 이벤트용)
    __u32 uid;            // 실행 사용자 UID
    char  comm[16];       // 프로세스 이름 (TASK_COMM_LEN)
    char  path[256];      // execve: argv[0], openat: 파일 경로
    __u32 remote_ip;      // tcp_connect: 목적지 IP (big-endian)
    __u16 remote_port;    // tcp_connect: 목적지 포트 (big-endian)
};
```

크기: 1 + 4*3 + 16 + 256 + 4 + 2 = **291 bytes/이벤트**  
256KB 링 버퍼 기준: 약 **900개 이벤트** 동시 버퍼링 가능

---

## 8. 로그 출력 형식

기존 `LOG|<ip>|<message>\n` 포맷 유지, 이벤트 태그만 추가:

```
LOG|172.17.0.2|[2026-03-05 00:15:36] EXEC pid=42 uid=0 comm=wget path=/usr/bin/wget
LOG|172.17.0.2|[2026-03-05 00:15:37] ALERT: REVERSE_SHELL DETECTED | pid=43 comm=nc remote=172.17.0.2:6666
LOG|172.17.0.2|[2026-03-05 00:15:38] FILE ACCESS: /etc/passwd by pid=44(cat)
LOG|172.17.0.2|[2026-03-05 00:15:39] FORK: pid=45 ppid=43 comm=sh
```

`renux_master`의 수신 파싱 로직 변경 없음 — `|` 구분 포맷 동일.

---

## 9. 보안 고려사항

### CAP_BPF 권한
eBPF 프로그램 로드는 루트 또는 `CAP_BPF` 권한 필요.  
Renux는 이미 루트로 실행되므로 추가 설정 불필요.

### BPF Verifier 제한 사항
| 제한 | 값 |
|------|-----|
| 최대 명령어 수 | 1,000,000 |
| 스택 크기 | 512 bytes |
| 맵 값 크기 | 최대 64KB |
| 동적 루프 | 제한적 허용 (5.3+) |

### 유저 공간 포인터 읽기
커널 eBPF에서 유저 메모리(argv 등)를 직접 역참조할 수 없다.
반드시 `bpf_probe_read_user_str()` 헬퍼 사용:

```c
// 올바른 방법
const char __user *filename = (const char __user *)ctx->args[1];
bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
```

---

## 10. 패키지 의존성 (Ubuntu 22.04)

**빌드 시:**
```
clang              ← BPF 오브젝트 컴파일 (-target bpf)
llvm               ← clang 의존
libbpf-dev         ← bpf/bpf_helpers.h, libbpf.h
linux-headers-generic  ← 커널 헤더
linux-tools-generic    ← bpftool (skeleton 생성)
libelf-dev         ← ELF 파싱 (-lelf)
zlib1g-dev         ← 압축 지원 (-lz)
```

**런타임 확인:**
```bash
# BTF 활성화 여부
ls /sys/kernel/btf/vmlinux

# 커널 버전
uname -r  # 5.8 이상이면 Ring Buffer 사용 가능
```

---

## 11. Docker 환경 제약

eBPF는 **호스트 커널**에서 실행되므로 컨테이너 테스트 시 권한 필요:

```bash
# 테스트 환경 (--privileged)
docker run --rm --privileged renux:test bash test/test_monitoring.sh

# 프로덕션 최소 권한
docker run --rm \
  --cap-add CAP_BPF \
  --cap-add CAP_SYS_ADMIN \
  --cap-add CAP_NET_ADMIN \
  renux:test ./renux
```

> **주의:** `--privileged` 컨테이너에서 로드한 eBPF 프로그램은 호스트 전체에 영향을 미친다. 테스트 환경 전용.

---

## 요약

| 항목 | 내용 |
|------|------|
| 핵심 라이브러리 | libbpf + bpftool skeleton |
| Hook 4종 | execve tracepoint, tcp_connect kprobe, openat tracepoint, fork tracepoint |
| 이벤트 전달 | BPF Ring Buffer 256KB |
| 최소 커널 | 5.8 (Ubuntu 22.04 = 5.15 ✅) |
| 권한 | CAP_BPF / root |
| 우회 불가 이유 | syscall 진입점 후킹 = 모든 프로세스가 반드시 통과 |
| 기존 재사용 | TLS 전송, 오프라인 버퍼, 설정 파싱, 로그 포맷 |
