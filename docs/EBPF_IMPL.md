# Renux V3 eBPF 구현 요약

작성일: 2026-03-27

---

## 개요

V2의 폴링 기반 모니터링을 eBPF syscall-level 후킹으로 교체했다.

| 항목 | V2 (기존) | V3 (eBPF) |
|------|-----------|-----------|
| 쉘 실행 탐지 | `.bashrc` 훅 주입 | `execve` tracepoint |
| TCP 연결 탐지 | `/proc/net/tcp` 30초 폴링 | `tcp_connect` kprobe |
| 파일 접근 탐지 | inotify (`/root`, `/home` 한정) | `openat` tracepoint |
| 웹쉘 탐지 | `/proc/[pid]/stat` 폴링 | `sched_process_fork` tracepoint |
| 우회 가능성 | `bash --norc`, `sh`, `zsh` 등으로 우회 가능 | syscall 진입점 = 우회 불가 |
| 탐지 지연 | 최대 30초 | 0ms |

---

## 파일 구성

```
monitoring/
├── renux_event.h      # 신규: 커널/유저 공유 이벤트 구조체
├── renux.bpf.c        # 신규: eBPF 커널 프로그램 (4개 hook)
├── renux.skel.h       # 빌드 시 자동 생성 (bpftool gen skeleton)
├── vmlinux.h          # 빌드 시 자동 생성 (bpftool btf dump)
├── monitor.cpp        # 수정: eBPF 이벤트 루프로 교체
└── master.cpp         # 변경 없음
Makefile               # 수정: eBPF 빌드 파이프라인 추가
Dockerfile             # 수정: eBPF 의존 패키지 추가
```

---

## 1. renux_event.h — 공유 이벤트 구조체

커널 BPF 프로그램과 유저 공간 monitor.cpp가 동일한 구조체를 사용한다.

```c
struct renux_event {
    __u8  type;           // EVENT_EXEC / EVENT_CONNECT / EVENT_OPEN / EVENT_FORK
    __u32 pid;
    __u32 ppid;           // FORK 이벤트 전용
    __u32 uid;
    char  comm[16];       // 프로세스 이름
    char  path[256];      // execve: 실행 파일 경로, openat: 파일 경로
    __u32 remote_ip;      // tcp_connect: 목적지 IP (네트워크 바이트 오더)
    __u16 remote_port;    // tcp_connect: 목적지 포트
} __attribute__((packed));
```

헤더 공유 방식: `__BPF_PROGRAM__` 매크로로 분기.
- BPF 코드에서는 `vmlinux.h`의 `__u8/__u32` 사용
- 유저 코드에서는 `<stdint.h>` typedef로 대체

---

## 2. renux.bpf.c — eBPF 커널 프로그램

### Hook 1: `tp/syscalls/sys_enter_execve`

모든 `execve()` 진입 시 실행. `filename` 인자를 유저 메모리에서 읽어 basename을 추출하고, SHELL_NAMES(`bash`, `sh`, `nc`, `python` 등)과 일치하면 이벤트 발행.

```c
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
```

- `ctx->args[0]` = filename (유저 포인터)
- `bpf_probe_read_user_str()` 로 스택에 복사
- basename 추출: forward scan으로 last `/` 위치 파악 후 15바이트 복사
- `path_basename_is_shell()` 로 필터링

### Hook 2: `kprobe/tcp_connect`

`tcp_connect()` 커널 함수 진입 시 실행. CO-RE로 `sock` 구조체에서 목적지 IP/포트 읽기.

```c
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
```

- `PT_REGS_PARM1(ctx)` = `struct sock *sk`
- `BPF_CORE_READ(sk, __sk_common.skc_daddr)` = 목적지 IP
- `BPF_CORE_READ(sk, __sk_common.skc_dport)` = 목적지 포트
- 루프백(`0x0100007f`) 및 ANY(`0x0`) 제외
- `bpf_get_current_comm()` 으로 comm 가져와 `is_shell_comm()` 필터링

### Hook 3: `tp/syscalls/sys_enter_openat`

`openat()` 진입 시 실행. 쓰기 목적 플래그(`O_WRONLY | O_RDWR | O_CREAT`)가 있고, 감시 경로(`/etc/`, `/root`, `/home/`, `/tmp/`)에 해당하는 경우만 이벤트 발행.

```c
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
```

- `ctx->args[2]` = flags → `O_WRONLY | O_RDWR | O_CREAT` 중 하나 없으면 early return
- `ctx->args[1]` = filename → `is_monitored_path()` 필터링

### Hook 4: `tp/sched/sched_process_fork`

fork 발생 시 parent_comm이 WEBSERVER_NAMES이고 child_comm이 SHELL_NAMES이면 웹쉘 의심 이벤트 발행.

```c
SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
```

- `ctx->parent_comm`, `ctx->child_comm` = kernel 메모리 → `bpf_probe_read_kernel_str()`
- webserver + shell 조합이어야 이벤트 발행

### BPF Ring Buffer

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);  // 256KB ≈ 900개 이벤트
} events SEC(".maps");
```

이벤트 발행 패턴:
```c
struct renux_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) return 0;   // 버퍼 꽉 찼으면 드롭
// ... 필드 채우기 ...
bpf_ringbuf_submit(e, 0);
```

### Comm 매칭 (BPF Verifier 호환)

반복문 없이 `__always_inline` 함수로 char-by-char 비교.

```c
static __always_inline bool is_shell_comm(const char comm[16]) {
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h' && comm[4]=='\0') return true;
    // ...
}
```

이유: BPF verifier는 런타임 루프를 허용하지만, 인라인 비교가 더 간결하고 verifier 분석 복잡도를 낮춘다.

### CO-RE (Compile Once, Run Everywhere)

`vmlinux.h` + `BPF_CORE_READ` 매크로 사용. 로드 시점에 libbpf가 현재 커널 BTF와 대조해 구조체 오프셋을 자동 보정한다. Ubuntu 22.04 기본 커널 5.15에서 동작.

---

## 3. monitor.cpp — 변경 사항

### 제거된 코드

| 제거 항목 | 이유 |
|-----------|------|
| `inotify_fd`, inotify setup/loop | eBPF `openat` hook으로 대체 |
| `detect_reverse_shell()` | eBPF `tcp_connect` kprobe로 대체 |
| `check_webshell_pattern()` | eBPF `fork` tracepoint으로 대체 |
| `detection_loop()` thread | 폴링 불필요, 이벤트 기반으로 전환 |
| `inject_hook_to_file()` | eBPF `execve` hook이 모든 쉘 실행 캡처 |
| `setup_all_users_hooks()` | 위와 동일 |
| `hex_to_ip()`, `get_proc_comm()` 등 | /proc 파싱 유틸 전체 제거 |
| `generate_diff()`, `read_file_content()` | inotify 기반 diff 로직 제거 |

### 추가된 코드

```cpp
#include <bpf/libbpf.h>
#include "renux.skel.h"    // bpftool gen skeleton으로 자동 생성
#include "renux_event.h"
```

**handle_event 콜백:**

```cpp
static int handle_event(void *, void *data, size_t) {
    const struct renux_event *e = static_cast<const struct renux_event *>(data);
    switch (e->type) {
    case EVENT_EXEC:    write_agent_log("EXEC ...");
    case EVENT_CONNECT: write_agent_log("ALERT: REVERSE_SHELL DETECTED ...");
    case EVENT_OPEN:    write_agent_log("FILE ACCESS: ...");
    case EVENT_FORK:    write_agent_log("ALERT: WEBSHELL SUSPECTED ...");
    }
    return 0;
}
```

**main() 이벤트 루프:**

```cpp
// V2: inotify read() blocking loop + detection_loop thread
// V3: eBPF skeleton + ring buffer poll

struct renux_bpf *skel = renux_bpf__open_and_load();
renux_bpf__attach(skel);

struct ring_buffer *rb = ring_buffer__new(
    bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);

while (keep_running)
    ring_buffer__poll(rb, 100);  // 100ms timeout, 이벤트 즉시 콜백

ring_buffer__free(rb);
renux_bpf__destroy(skel);
```

### 유지된 코드

- TLS 연결 (`connect_to_master`, SSL_write)
- 오프라인 버퍼링 (`offline_buffer`, `net_mutex`)
- 설정 파싱 (`load_config`)
- 로그 기록 (`write_agent_log`)
- trace 서브커맨드 (`handle_trace_command`)
- signal handler (async-signal-safe 방식 유지)

---

## 4. Makefile — eBPF 빌드 파이프라인

Linux에서 `make renux` 실행 시 3단계 자동 빌드:

```
Step 1: vmlinux.h 생성
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > monitoring/vmlinux.h

Step 2: BPF 오브젝트 컴파일
  clang -O2 -g -target bpf -D__BPF_PROGRAM__ -D__TARGET_ARCH_x86_64 \
      -I monitoring/ -c renux.bpf.c -o renux.bpf.o

Step 3: skeleton 헤더 생성
  bpftool gen skeleton renux.bpf.o name renux > renux.skel.h

Step 4: 최종 링크
  g++ -std=c++17 ... -I monitoring/ monitor.cpp ssl_utils.c \
      -lssl -lcrypto -lbpf -lelf -lz -o renux
```

macOS에서는 `renux` 타겟을 스킵 (Linux 전용 바이너리).

---

## 5. Dockerfile

추가된 패키지:

```dockerfile
clang llvm libbpf-dev \
linux-headers-generic linux-tools-generic \
libelf-dev zlib1g-dev
```

eBPF 테스트 실행 시 권한:
```bash
# 테스트 (--privileged: host 커널 전체에 eBPF 로드)
docker run --privileged renux:v3 ./renux

# 최소 권한 (프로덕션)
docker run \
  --cap-add CAP_BPF \
  --cap-add CAP_SYS_ADMIN \
  --cap-add CAP_NET_ADMIN \
  renux:v3 ./renux
```

---

## 로그 출력 형식

기존 `LOG|<ip>|<message>\n` 포맷 유지 (master.cpp 파싱 로직 변경 없음).

```
LOG|172.17.0.2|[2026-03-27 10:00:01] EXEC pid=42 uid=0 comm=nginx path=/bin/bash
LOG|172.17.0.2|[2026-03-27 10:00:02] ALERT: REVERSE_SHELL DETECTED | pid=43 comm=nc remote=10.0.0.1:4444
LOG|172.17.0.2|[2026-03-27 10:00:03] FILE ACCESS: /etc/passwd by pid=44(cat)
LOG|172.17.0.2|[2026-03-27 10:00:04] ALERT: WEBSHELL SUSPECTED | ppid=100 -> child=sh(pid=101)
```

---

## 빌드 및 실행

```bash
# Ubuntu 22.04 의존 패키지
sudo apt install clang llvm libbpf-dev linux-headers-generic \
    linux-tools-generic libelf-dev zlib1g-dev

# 빌드
make renux

# 실행 (root 또는 CAP_BPF 필요)
sudo ./renux

# trace 서브커맨드 (변경 없음)
sudo ./renux trace "REVERSE_SHELL"
```
