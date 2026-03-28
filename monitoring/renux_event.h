#pragma once

/*
 * renux_event.h — shared between renux.bpf.c (kernel) and monitor.cpp (userspace)
 *
 * In BPF code, define __BPF_PROGRAM__ before including to use kernel types.
 * In userspace code, stdint types are used automatically.
 */

#ifndef __BPF_PROGRAM__
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#endif

#define EVENT_EXEC    1   /* execve: a shell/tool was executed          */
#define EVENT_CONNECT 2   /* tcp_connect: shell made external TCP conn  */
#define EVENT_OPEN    3   /* openat: write-mode open on sensitive path  */
#define EVENT_FORK    4   /* sched_process_fork: webserver spawned shell */

struct renux_event {
    __u8  type;           /* EVENT_* above                              */
    __u32 pid;            /* process PID                                */
    __u32 ppid;           /* parent PID (FORK event)                    */
    __u32 uid;            /* effective UID                              */
    char  comm[16];       /* process comm (TASK_COMM_LEN)               */
    char  path[256];      /* execve: filename, openat: file path        */
    char  args[256];      /* execve: argv[1..8] space-joined            */
    __u32 remote_ip;      /* tcp_connect: dest IP (network byte order)  */
    __u16 remote_port;    /* tcp_connect: dest port (network byte order)*/
} __attribute__((packed));
