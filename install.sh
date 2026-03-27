#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────
#  Renux Installer
#  지원 OS: CentOS 7/8/9, Rocky Linux 8/9, Ubuntu
#  eBPF slave: 커널 5.8+ 이상인 경우에만 설치 가능
# ─────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── 유틸리티 ──────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || error "root 권한이 필요합니다. sudo $0 으로 실행하세요."
}

# ── OS 감지 ───────────────────────────────────────────────────────────

OS_ID=""
OS_VERSION=""
OS_PRETTY=""
PKG_MANAGER=""

detect_os() {
    if [ ! -f /etc/os-release ]; then
        error "지원하지 않는 OS입니다."
    fi

    . /etc/os-release
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID%%.*}"   # 8.9 → 8
    OS_PRETTY="${PRETTY_NAME}"

    case "${OS_ID}" in
        ubuntu)               PKG_MANAGER="apt"  ;;
        centos|rhel|rocky|almalinux) PKG_MANAGER="dnf" ;;
        *)                    error "지원하지 않는 OS: ${OS_ID}" ;;
    esac

    # CentOS/RHEL 7은 dnf 없음 → yum 사용
    if [ "${OS_ID}" = "centos" ] && [ "${OS_VERSION}" = "7" ]; then
        PKG_MANAGER="yum"
    fi
}

# ── 커널 버전 체크 ────────────────────────────────────────────────────

KERNEL_MAJOR=0
KERNEL_MINOR=0
EBPF_SUPPORTED=false

check_kernel() {
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)

    if [ "${KERNEL_MAJOR}" -gt 5 ] || \
       ([ "${KERNEL_MAJOR}" -eq 5 ] && [ "${KERNEL_MINOR}" -ge 8 ]); then
        EBPF_SUPPORTED=true
    fi
}

# ── 의존 패키지 설치 ──────────────────────────────────────────────────

COMMON_DEPS_APT="gcc g++ make libssl-dev libcap-dev libncurses-dev"
EBPF_DEPS_APT="clang llvm libbpf-dev linux-headers-generic linux-tools-generic libelf-dev zlib1g-dev"

COMMON_DEPS_DNF="gcc gcc-c++ make openssl-devel libcap-devel ncurses-devel"
EBPF_DEPS_DNF_ROCKY9="clang llvm libbpf-devel bpftool kernel-headers elfutils-libelf-devel zlib-devel"
EBPF_DEPS_DNF_ROCKY8="clang llvm libbpf-devel kernel-headers elfutils-libelf-devel zlib-devel"

install_deps_master_apt() {
    info "패키지 설치 중 (Ubuntu - master)..."
    apt-get update -q
    apt-get install -y ${COMMON_DEPS_APT}
    ok "패키지 설치 완료"
}

install_deps_slave_apt() {
    info "패키지 설치 중 (Ubuntu - slave + eBPF)..."
    apt-get update -q
    apt-get install -y ${COMMON_DEPS_APT} ${EBPF_DEPS_APT}
    ok "패키지 설치 완료"
}

install_deps_master_dnf() {
    info "패키지 설치 중 (${OS_PRETTY} - master)..."
    ${PKG_MANAGER} install -y ${COMMON_DEPS_DNF}
    ok "패키지 설치 완료"
}

install_deps_slave_dnf() {
    info "패키지 설치 중 (${OS_PRETTY} - slave + eBPF)..."

    # Rocky/CentOS 9: EPEL 없이 base repo에서 설치 가능
    # Rocky/CentOS 8: EPEL 필요할 수 있음
    if [ "${OS_VERSION}" -le 8 ]; then
        info "EPEL 저장소 활성화 중..."
        ${PKG_MANAGER} install -y epel-release 2>/dev/null || true
        ${PKG_MANAGER} install -y ${COMMON_DEPS_DNF} ${EBPF_DEPS_DNF_ROCKY8}
    else
        ${PKG_MANAGER} install -y ${COMMON_DEPS_DNF} ${EBPF_DEPS_DNF_ROCKY9}
    fi

    ok "패키지 설치 완료"
}

install_deps_master_yum() {
    info "패키지 설치 중 (CentOS 7 - master)..."
    yum install -y epel-release
    yum install -y ${COMMON_DEPS_DNF}
    ok "패키지 설치 완료"
}

install_deps_slave_yum() {
    info "패키지 설치 중 (CentOS 7 - slave + eBPF, 커널 업그레이드 필요)..."
    yum install -y epel-release
    # ELRepo kernel-ml 사용 시 libbpf/bpftool 설치 경로
    yum install -y ${COMMON_DEPS_DNF} \
        clang llvm elfutils-libelf-devel zlib-devel

    # CentOS 7에서는 libbpf-devel, bpftool이 없을 수 있어 소스 빌드 안내
    if ! rpm -q libbpf-devel &>/dev/null && ! rpm -q bpftool &>/dev/null; then
        warn "libbpf-devel / bpftool 패키지를 찾을 수 없습니다."
        warn "ELRepo kernel-ml 또는 수동 빌드가 필요할 수 있습니다."
        warn "  참고: https://elrepo.org/"
    fi

    ok "패키지 설치 완료 (일부 패키지 수동 확인 필요)"
}

# ── 빌드 ──────────────────────────────────────────────────────────────

INSTALL_DIR="${PWD}"

build_master() {
    info "Master 빌드 중..."
    make renux_master server_e client_e
    ok "Master 빌드 완료: renux_master, server_e, client_e"
}

build_slave() {
    info "Slave (eBPF agent) 빌드 중..."

    # vmlinux.h가 없으면 생성
    if [ ! -f monitoring/vmlinux.h ]; then
        info "vmlinux.h 생성 중..."
        if ! bpftool btf dump file /sys/kernel/btf/vmlinux format c > monitoring/vmlinux.h 2>/dev/null; then
            # bpftool 명령어 위치가 다를 수 있음 (Rocky/CentOS)
            BPFTOOL=$(command -v bpftool || find /usr -name bpftool 2>/dev/null | head -1)
            if [ -z "${BPFTOOL}" ]; then
                error "bpftool을 찾을 수 없습니다. linux-tools-generic 또는 bpftool 패키지를 확인하세요."
            fi
            ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > monitoring/vmlinux.h
        fi
        ok "vmlinux.h 생성 완료"
    fi

    make renux
    ok "Slave 빌드 완료: renux"
}

# ── systemd 서비스 등록 ───────────────────────────────────────────────

MASTER_IP_INPUT=""
MASTER_PORT_INPUT="9000"

setup_master_service() {
    info "renux_master systemd 서비스 등록 중..."

    cp renux_master /usr/local/bin/renux_master
    chmod 755 /usr/local/bin/renux_master

    cat > /etc/systemd/system/renux-master.service <<EOF
[Unit]
Description=Renux Master Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/renux_master
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable renux-master
    ok "renux-master 서비스 등록 완료"
}

setup_slave_service() {
    info "renux (slave) systemd 서비스 등록 중..."

    cp renux /usr/local/bin/renux
    chmod 755 /usr/local/bin/renux

    # TLS 인증서 디렉토리
    mkdir -p /etc/renux

    cat > /etc/systemd/system/renux.service <<EOF
[Unit]
Description=Renux Monitoring Agent (eBPF)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/renux
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable renux
    ok "renux 서비스 등록 완료"
}

# ── 설정 파일 ─────────────────────────────────────────────────────────

configure_slave() {
    echo ""
    echo -e "${CYAN}Master 서버 정보를 입력하세요${NC}"
    read -p "  Master IP   : " MASTER_IP_INPUT
    read -p "  Master Port [9000]: " MASTER_PORT_INPUT
    MASTER_PORT_INPUT="${MASTER_PORT_INPUT:-9000}"

    cat > /etc/renux.conf <<EOF
MASTER_IP=${MASTER_IP_INPUT}
MASTER_PORT=${MASTER_PORT_INPUT}
EOF

    ok "/etc/renux.conf 작성 완료"
}

# ── 메인 ──────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ██████╗ ███████╗███╗   ██╗██╗   ██╗██╗  ██╗"
    echo "  ██╔══██╗██╔════╝████╗  ██║██║   ██║╚██╗██╔╝"
    echo "  ██████╔╝█████╗  ██╔██╗ ██║██║   ██║ ╚███╔╝ "
    echo "  ██╔══██╗██╔══╝  ██║╚██╗██║██║   ██║ ██╔██╗ "
    echo "  ██║  ██║███████╗██║ ╚████║╚██████╔╝██╔╝ ██╗"
    echo "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}Renux Installer${NC}"
    echo ""
}

print_sysinfo() {
    echo -e "  OS     : ${OS_PRETTY}"
    echo -e "  Kernel : $(uname -r)"
    if [ "${EBPF_SUPPORTED}" = true ]; then
        echo -e "  eBPF   : ${GREEN}지원됨 (커널 ${KERNEL_MAJOR}.${KERNEL_MINOR} ≥ 5.8)${NC}"
    else
        echo -e "  eBPF   : ${YELLOW}미지원 (커널 ${KERNEL_MAJOR}.${KERNEL_MINOR} < 5.8)${NC}"
    fi
    echo ""
}

main() {
    require_root
    detect_os
    check_kernel

    print_banner
    print_sysinfo

    # ── 설치 메뉴 ─────────────────────────────────────────────────────

    if [ "${EBPF_SUPPORTED}" = true ]; then
        echo -e "  ${BOLD}설치 유형을 선택하세요${NC}"
        echo ""
        echo "    1) Master  — 중앙 로그 서버 (renux_master, server_e, client_e)"
        echo "    2) Slave   — 모니터링 에이전트 (renux, eBPF)"
        echo ""
        read -p "  선택 [1/2]: " CHOICE
    else
        echo -e "  ${YELLOW}커널 5.8 미만 — eBPF Slave 설치 불가.${NC}"
        echo -e "  Master만 설치할 수 있습니다."
        echo ""
        echo "    1) Master  — 중앙 로그 서버 (renux_master, server_e, client_e)"
        echo "    q) 종료"
        echo ""
        read -p "  선택 [1/q]: " CHOICE
        [ "${CHOICE}" = "q" ] && exit 0
    fi

    echo ""

    case "${CHOICE}" in
        1)
            info "=== Master 설치 시작 ==="
            case "${PKG_MANAGER}" in
                apt) install_deps_master_apt ;;
                dnf) install_deps_master_dnf ;;
                yum) install_deps_master_yum ;;
            esac
            build_master
            setup_master_service
            echo ""
            ok "=== Master 설치 완료 ==="
            echo ""
            echo -e "  시작: ${CYAN}systemctl start renux-master${NC}"
            echo -e "  로그: ${CYAN}journalctl -u renux-master -f${NC}"
            ;;

        2)
            if [ "${EBPF_SUPPORTED}" != true ]; then
                error "eBPF Slave는 커널 5.8 이상에서만 설치 가능합니다."
            fi
            info "=== Slave 설치 시작 ==="
            case "${PKG_MANAGER}" in
                apt) install_deps_slave_apt ;;
                dnf) install_deps_slave_dnf ;;
                yum) install_deps_slave_yum ;;
            esac
            configure_slave
            build_slave
            setup_slave_service
            echo ""
            ok "=== Slave 설치 완료 ==="
            echo ""
            echo -e "  시작: ${CYAN}systemctl start renux${NC}"
            echo -e "  로그: ${CYAN}journalctl -u renux -f${NC}"
            echo -e "  설정: ${CYAN}/etc/renux.conf${NC}"
            ;;

        *)
            error "잘못된 선택입니다."
            ;;
    esac

    echo ""
}

main "$@"
