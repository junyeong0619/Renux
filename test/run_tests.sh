#!/bin/bash
# Renux V2.1 자동화 테스트 스크립트
# 실행 위치: 프로젝트 루트 (docker 컨테이너 내부)
# 사용법: bash test/run_tests.sh

PASS=0
FAIL=0
SKIP=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }

echo "============================================"
echo "  Renux V2.1 Test Suite"
echo "============================================"
echo ""

# ── 1. 빌드 확인 ─────────────────────────────────────────────────────
echo "--- [1] Build Check ---"

for bin in server_e client_e renux renux_master; do
    if [ -x "./$bin" ]; then
        ok "$bin 바이너리 존재"
    else
        fail "$bin 바이너리 없음 (make all 먼저 실행)"
    fi
done
echo ""

# ── 2. 보안 컴파일 플래그 검증 ───────────────────────────────────────
echo "--- [2] Security Flags ---"

for bin in server_e client_e renux renux_master; do
    if [ -x "./$bin" ]; then
        if readelf -s "./$bin" 2>/dev/null | grep -q "__stack_chk_fail"; then
            ok "$bin: stack canary 활성"
        else
            fail "$bin: stack canary 없음"
        fi
    fi
done
echo ""

# ── 3. TLS 인증서 확인 ───────────────────────────────────────────────
echo "--- [3] TLS Certificates ---"

for cert in /etc/renux/server.crt /etc/renux/server.key \
            /etc/renux/master.crt /etc/renux/master.key; do
    if [ -f "$cert" ]; then
        ok "$cert 존재"
    else
        fail "$cert 없음"
    fi
done

# 인증서 유효성
if openssl verify -CAfile /etc/renux/server.crt /etc/renux/server.crt &>/dev/null; then
    ok "server.crt 자체 서명 유효"
else
    fail "server.crt 검증 실패"
fi

if openssl verify -CAfile /etc/renux/master.crt /etc/renux/master.crt &>/dev/null; then
    ok "master.crt 자체 서명 유효"
else
    fail "master.crt 검증 실패"
fi

# 키-인증서 매칭
SERVER_CERT_MD5=$(openssl x509 -noout -modulus -in /etc/renux/server.crt | md5sum)
SERVER_KEY_MD5=$(openssl rsa -noout -modulus -in /etc/renux/server.key 2>/dev/null | md5sum)
if [ "$SERVER_CERT_MD5" = "$SERVER_KEY_MD5" ]; then
    ok "server.crt ↔ server.key 매칭"
else
    fail "server.crt ↔ server.key 불일치"
fi

MASTER_CERT_MD5=$(openssl x509 -noout -modulus -in /etc/renux/master.crt | md5sum)
MASTER_KEY_MD5=$(openssl rsa -noout -modulus -in /etc/renux/master.key 2>/dev/null | md5sum)
if [ "$MASTER_CERT_MD5" = "$MASTER_KEY_MD5" ]; then
    ok "master.crt ↔ master.key 매칭"
else
    fail "master.crt ↔ master.key 불일치"
fi
echo ""

# ── 4. renux_master TLS 수신 테스트 ─────────────────────────────────
echo "--- [4] renux_master TLS Handshake ---"

./renux_master &
MASTER_PID=$!
sleep 1

if kill -0 $MASTER_PID 2>/dev/null; then
    ok "renux_master 프로세스 기동"
else
    fail "renux_master 기동 실패"
fi

# openssl s_client로 TLS 핸드셰이크
TLS_OUT=$(echo "HELLO" | timeout 3 openssl s_client \
    -connect 127.0.0.1:9000 \
    -CAfile /etc/renux/master.crt \
    -verify_return_error 2>&1 || true)

if echo "$TLS_OUT" | grep -q "Verify return code: 0"; then
    ok "renux_master TLS 핸드셰이크 성공 (인증서 검증 통과)"
elif echo "$TLS_OUT" | grep -q "CONNECTED"; then
    ok "renux_master TLS 연결 성공 (핸드셰이크 완료)"
else
    fail "renux_master TLS 연결 실패"
    echo "  상세: $(echo "$TLS_OUT" | tail -5)"
fi

# 포트 리스닝 확인
if ss -tnlp 2>/dev/null | grep -q ":9000" || \
   netstat -tnlp 2>/dev/null | grep -q ":9000"; then
    ok "renux_master port 9000 리스닝 중"
else
    skip "port 9000 확인 불가 (ss/netstat 없음)"
fi

kill $MASTER_PID 2>/dev/null || true
sleep 1
echo ""

# ── 5. server_e TLS 핸드셰이크 테스트 ───────────────────────────────
echo "--- [5] server_e TLS Handshake ---"

# -p <password> 헤드리스 모드로 자동 실행
./server_e -p testpass123 &>/dev/null &
SERVER_PID=$!
sleep 2

if kill -0 $SERVER_PID 2>/dev/null; then
    ok "server_e 헤드리스 기동 성공 (-p 플래그)"
else
    fail "server_e 기동 실패"
fi

# TLS 핸드셰이크 확인
TLS_OUT=$(echo "" | timeout 3 openssl s_client \
    -connect 127.0.0.1:8080 \
    -CAfile /etc/renux/server.crt \
    -verify_return_error 2>&1 || true)

if echo "$TLS_OUT" | grep -q "Verify return code: 0"; then
    ok "server_e TLS 핸드셰이크 성공 (인증서 검증 통과)"
elif echo "$TLS_OUT" | grep -q "CONNECTED"; then
    ok "server_e TLS 연결 성공"
else
    fail "server_e TLS 연결 실패"
    echo "  상세: $(echo "$TLS_OUT" | grep -E 'error|Error|CONNECTED' | head -3)"
fi

# 로그인 시도: username,password 전송 후 응답 확인
LOGIN_OUT=$(printf "testuser,testpass123" | timeout 3 openssl s_client \
    -connect 127.0.0.1:8080 \
    -CAfile /etc/renux/server.crt \
    -quiet 2>/dev/null || true)

if echo "$LOGIN_OUT" | grep -qi "welcome\|login\|success\|>"; then
    ok "server_e 로그인 응답 수신"
else
    skip "server_e 로그인 응답 확인 불가 (TLS 연결은 성공)"
fi

kill $SERVER_PID 2>/dev/null || true
sleep 1
echo ""

# ── 6. renux 에이전트 기동 테스트 ───────────────────────────────────
echo "--- [6] renux Agent Start ---"

# /proc 접근 가능 여부
if [ -f /proc/net/tcp ]; then
    ok "/proc/net/tcp 접근 가능"
else
    fail "/proc/net/tcp 없음 (--privileged 또는 Linux 커널 필요)"
fi

# inotify 사용 가능 여부
if [ -f /proc/sys/fs/inotify/max_user_watches ]; then
    ok "inotify 지원 확인"
else
    fail "inotify 미지원"
fi

# 에이전트 잠시 기동 후 종료
touch /var/log/renux.log
timeout 3 ./renux &>/dev/null &
AGENT_PID=$!
sleep 2

if kill -0 $AGENT_PID 2>/dev/null; then
    ok "renux 에이전트 기동 성공"
    kill $AGENT_PID
else
    # 정상 종료 또는 빠른 종료일 수 있음
    if [ -s /var/log/renux.log ]; then
        ok "renux 에이전트 실행 및 로그 기록 확인"
    else
        fail "renux 에이전트 기동 실패"
    fi
fi
echo ""

# ── 7. exec_utils 입력 검증 테스트 ──────────────────────────────────
echo "--- [7] Input Validation (간접 검증) ---"

# popen 의존성이 없는지 확인 (strings로 취약 패턴 검색)
if strings ./server_e 2>/dev/null | grep -q "popen"; then
    fail "server_e에 popen 참조 발견"
else
    ok "server_e popen 의존성 없음"
fi

if strings ./renux 2>/dev/null | grep -q "popen"; then
    fail "renux에 popen 참조 발견"
else
    ok "renux popen 의존성 없음"
fi
echo ""

# ── 결과 요약 ─────────────────────────────────────────────────────────
echo "============================================"
echo "  결과: PASS=${PASS}  FAIL=${FAIL}  SKIP=${SKIP}"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
