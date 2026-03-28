#!/usr/bin/env python3
"""
Renux mock agent simulator
여러 가짜 슬레이브가 master에 연결해 실시간 로그를 전송합니다.

Usage:
    python3 mock_agents.py [master_ip] [master_port]

Default: 127.0.0.1:9000
"""

import ssl
import socket
import time
import random
import threading
import sys

MASTER_IP   = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
MASTER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

FAKE_IPS = [
    "10.0.0.11",
    "10.0.0.12",
    "10.0.0.13",
    "10.0.0.14",
]

NORMAL_LOGS = [
    "EXEC pid={pid} uid=0 comm=bash path=/bin/ls",
    "EXEC pid={pid} uid=1000 comm=sh path=/usr/bin/whoami",
    "EXEC pid={pid} uid=0 comm=bash path=/usr/bin/find",
    "FILE ACCESS: /etc/passwd by pid={pid}(cat)",
    "FILE ACCESS: /etc/shadow by pid={pid}(grep)",
    "FILE ACCESS: /home/user/.ssh/authorized_keys by pid={pid}(vim)",
    "FILE ACCESS: /tmp/upload.php by pid={pid}(nginx)",
    "EXEC pid={pid} uid=33 comm=python3 path=/usr/bin/python3",
    "EXEC pid={pid} uid=0 comm=bash path=/bin/netstat",
    "FILE ACCESS: /root/.bash_history by pid={pid}(bash)",
]

ALERT_LOGS = [
    "ALERT: REVERSE_SHELL DETECTED | pid={pid} comm=bash remote=1.2.3.4:4444",
    "ALERT: REVERSE_SHELL DETECTED | pid={pid} comm=sh remote=192.168.1.99:9001",
    "ALERT: REVERSE_SHELL DETECTED | pid={pid} comm=python3 remote=10.10.10.5:8888",
    "ALERT: WEBSHELL SUSPECTED | ppid={ppid} -> child=bash(pid={pid})",
    "ALERT: WEBSHELL SUSPECTED | ppid={ppid} -> child=sh(pid={pid})",
]

def random_pid():
    return random.randint(1000, 65000)

def run_agent(fake_ip):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    while True:
        try:
            sock = socket.create_connection((MASTER_IP, MASTER_PORT), timeout=5)
            tls  = ctx.wrap_socket(sock)

            hello = f"HELLO|{fake_ip}|Renux Agent V3 Started\n"
            tls.sendall(hello.encode())
            print(f"[+] {fake_ip} connected")

            while True:
                time.sleep(random.uniform(0.8, 2.5))

                pid  = random_pid()
                ppid = random_pid()

                if random.random() < 0.15:   # 15% 확률로 ALERT
                    template = random.choice(ALERT_LOGS)
                else:
                    template = random.choice(NORMAL_LOGS)

                msg = template.format(pid=pid, ppid=ppid)
                tls.sendall(f"LOG|{fake_ip}|{msg}\n".encode())

        except (ConnectionRefusedError, OSError) as e:
            print(f"[-] {fake_ip} disconnected ({e}), retrying in 5s...")
            time.sleep(5)

threads = []
for ip in FAKE_IPS:
    t = threading.Thread(target=run_agent, args=(ip,), daemon=True)
    t.start()
    threads.append(t)
    time.sleep(0.3)

print(f"\n{len(FAKE_IPS)} mock agents running → {MASTER_IP}:{MASTER_PORT}")
print("Ctrl+C to stop\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped.")
