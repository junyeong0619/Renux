// SPDX-License-Identifier: GPL-2.0
/*
 * renux.bpf.c — Renux V3 eBPF kernel program
 *
 * Hook points:
 *   1. tp/syscalls/sys_enter_execve  — shell/tool execution
 *   2. kprobe/tcp_connect            — reverse shell detection (0ms latency)
 *   3. tp/syscalls/sys_enter_openat  — write-mode open on sensitive paths
 *   4. tp/sched/sched_process_fork   — webshell: webserver spawning a shell
 *
 * Build:
 *   clang -O2 -g -target bpf -D__BPF_PROGRAM__ -D__TARGET_ARCH_x86_64 \
 *         -I monitoring/ -c renux.bpf.c -o renux.bpf.o
 *   bpftool gen skeleton renux.bpf.o name renux > renux.skel.h
 */

#define __BPF_PROGRAM__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "renux_event.h"

char LICENSE[] SEC("license") = "GPL";

/* ── Ring Buffer ─────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);  /* 256 KB */
} events SEC(".maps");

/* ── O_* flag constants (linux/fcntl.h) ─────────────────────────────── */
#define O_WRONLY  1
#define O_RDWR    2
#define O_CREAT   64  /* 0100 octal */

/* ── 127.0.0.1 in network byte order on little-endian (x86_64) ───────── */
#define IP_LOOPBACK 0x0100007fU
#define IP_ANY      0x00000000U

/* ── Comm matching helpers ───────────────────────────────────────────── */

static __always_inline bool is_shell_comm(const char comm[16]) {
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h' && comm[4]=='\0') return true;
    if (comm[0]=='s' && comm[1]=='h'  && comm[2]=='\0') return true;
    if (comm[0]=='d' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h' && comm[4]=='\0') return true;
    if (comm[0]=='z' && comm[1]=='s' && comm[2]=='h'  && comm[3]=='\0') return true;
    if (comm[0]=='n' && comm[1]=='c'  && comm[2]=='\0') return true;
    if (comm[0]=='n' && comm[1]=='c' && comm[2]=='a' && comm[3]=='t' && comm[4]=='\0') return true;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h' && comm[4]=='o' && comm[5]=='n' && comm[6]=='\0') return true;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h' && comm[4]=='o' && comm[5]=='n' && comm[6]=='3' && comm[7]=='\0') return true;
    if (comm[0]=='p' && comm[1]=='e' && comm[2]=='r' && comm[3]=='l' && comm[4]=='\0') return true;
    if (comm[0]=='r' && comm[1]=='u' && comm[2]=='b' && comm[3]=='y' && comm[4]=='\0') return true;
    return false;
}

static __always_inline bool is_webserver_comm(const char comm[16]) {
    if (comm[0]=='h' && comm[1]=='t' && comm[2]=='t' && comm[3]=='p' && comm[4]=='d' && comm[5]=='\0') return true;
    if (comm[0]=='a' && comm[1]=='p' && comm[2]=='a' && comm[3]=='c' && comm[4]=='h' && comm[5]=='e' && comm[6]=='2' && comm[7]=='\0') return true;
    if (comm[0]=='n' && comm[1]=='g' && comm[2]=='i' && comm[3]=='n' && comm[4]=='x' && comm[5]=='\0') return true;
    if (comm[0]=='l' && comm[1]=='i' && comm[2]=='g' && comm[3]=='h' && comm[4]=='t' && comm[5]=='t' && comm[6]=='p' && comm[7]=='d' && comm[8]=='\0') return true;
    if (comm[0]=='p' && comm[1]=='h' && comm[2]=='p' && comm[3]=='-' && comm[4]=='f' && comm[5]=='p' && comm[6]=='m' && comm[7]=='\0') return true;
    if (comm[0]=='p' && comm[1]=='h' && comm[2]=='p' && comm[3]=='\0') return true;
    if (comm[0]=='u' && comm[1]=='w' && comm[2]=='s' && comm[3]=='g' && comm[4]=='i' && comm[5]=='\0') return true;
    return false;
}


/* Check if path starts with a monitored prefix */
static __always_inline bool is_monitored_path(const char path[256]) {
    if (path[0] != '/') return false;
    /* /etc/ */
    if (path[1]=='e' && path[2]=='t' && path[3]=='c' && path[4]=='/') return true;
    /* /root */
    if (path[1]=='r' && path[2]=='o' && path[3]=='o' && path[4]=='t') return true;
    /* /home/ */
    if (path[1]=='h' && path[2]=='o' && path[3]=='m' && path[4]=='e' && path[5]=='/') return true;
    /* /tmp/ */
    if (path[1]=='t' && path[2]=='m' && path[3]=='p' && path[4]=='/') return true;
    return false;
}

/* ── Hook 1: sys_enter_execve ────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    /* 루프 없이 comm으로 판단: 쉘 프로세스가 execve를 호출할 때만 기록.
     * path_basename_is_shell()의 256-byte 루프가 BPF verifier 명령어
     * 한도(1,000,000)를 초과하므로 제거하고 bpf_get_current_comm() 사용. */
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_shell_comm(comm)) return 0;

    char path[256] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const char *)ctx->args[0]);

    struct renux_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type        = EVENT_EXEC;
    e->pid         = bpf_get_current_pid_tgid() >> 32;
    e->ppid        = 0;
    e->uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->remote_ip   = 0;
    e->remote_port = 0;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    __builtin_memcpy(e->path, path, sizeof(e->path));

    /* argv[1..4] 읽기: 매크로로 unroll — verifier 루프 한도 우회 */
    const char **argv_ptr = (const char **)ctx->args[1];
    __builtin_memset(e->args, 0, sizeof(e->args));
    int pos = 0;

#define READ_ARG(N)                                                          \
    {                                                                        \
        const char *_ap = NULL;                                              \
        bpf_probe_read_user(&_ap, sizeof(_ap), argv_ptr + (N));             \
        if (_ap && pos >= 0 && pos < (int)(sizeof(e->args) - 1)) {         \
            if (pos > 0) { e->args[pos] = ' '; pos++; }                    \
            int _n = bpf_probe_read_user_str(e->args + pos,                 \
                         sizeof(e->args) - pos < 30                         \
                             ? sizeof(e->args) - pos : 30, _ap);            \
            if (_n > 1) pos += _n - 1;                                      \
            if (pos < 0 || pos >= (int)sizeof(e->args))                     \
                pos = (int)sizeof(e->args) - 1;                             \
        }                                                                    \
    }

    READ_ARG(1)
    READ_ARG(2)
    READ_ARG(3)
    READ_ARG(4)
    READ_ARG(5)
    READ_ARG(6)
    READ_ARG(7)
    READ_ARG(8)
#undef READ_ARG

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 2: kprobe/tcp_connect ──────────────────────────────────────── */

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    __u32 dst_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    /* Skip loopback and unbound */
    if (dst_ip == IP_LOOPBACK || dst_ip == IP_ANY) return 0;

    /* Only alert when a shell process makes an external connection */
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_shell_comm(comm)) return 0;

    struct renux_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type        = EVENT_CONNECT;
    e->pid         = bpf_get_current_pid_tgid() >> 32;
    e->ppid        = 0;
    e->uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->remote_ip   = dst_ip;
    e->remote_port = dst_port;
    e->path[0]     = '\0';
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 3: sys_enter_openat ────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* args[0]=dfd, args[1]=filename, args[2]=flags */
    int flags = (int)ctx->args[2];
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT))) return 0;

    char path[256] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const char *)ctx->args[1]);

    if (!is_monitored_path(path)) return 0;

    struct renux_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type        = EVENT_OPEN;
    e->pid         = bpf_get_current_pid_tgid() >> 32;
    e->ppid        = 0;
    e->uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->remote_ip   = 0;
    e->remote_port = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, path, sizeof(e->path));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Hook 4: sched_process_fork ─────────────────────────────────────── */

SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    /* Only care about webserver → shell forks */
    char parent_comm[16] = {};
    char child_comm[16]  = {};

    bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm), ctx->parent_comm);
    bpf_probe_read_kernel_str(child_comm,  sizeof(child_comm),  ctx->child_comm);

    if (!is_webserver_comm(parent_comm)) return 0;
    if (!is_shell_comm(child_comm))      return 0;

    struct renux_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type        = EVENT_FORK;
    e->pid         = ctx->child_pid;
    e->ppid        = ctx->parent_pid;
    e->uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->remote_ip   = 0;
    e->remote_port = 0;
    __builtin_memcpy(e->comm, child_comm, sizeof(e->comm));
    e->path[0]     = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}
