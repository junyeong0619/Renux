#!/bin/bash
set -e

echo "=================================================="
echo "  Renux V2.0 Installation Script"
echo "=================================================="

# ── 1. 의존성 설치 ────────────────────────────────────
echo ""
echo "--- [1/5] Installing Dependencies ---"

if command -v apt-get &>/dev/null; then
    sudo apt-get update -q
    sudo apt-get install -y \
        libssl-dev libcap-dev libncurses-dev \
        gcc g++ make
elif command -v yum &>/dev/null; then
    sudo yum install -y \
        openssl-devel libcap-devel ncurses-devel \
        gcc gcc-c++ make
elif command -v dnf &>/dev/null; then
    sudo dnf install -y \
        openssl-devel libcap-devel ncurses-devel \
        gcc gcc-c++ make
else
    echo "Warning: Unknown package manager. Please install manually:"
    echo "  libssl-dev, libcap-dev, libncurses-dev"
fi

# ── 2. 빌드 ──────────────────────────────────────────
echo ""
echo "--- [2/5] Building Binaries ---"

# devtoolset (CentOS 구버전 환경 지원)
if [ -f /opt/rh/devtoolset-9/enable ]; then
    source /opt/rh/devtoolset-9/enable
fi

make clean
make all

if [ $? -ne 0 ]; then
    echo "Compilation failed. Check GCC version (C++17 required) and dependencies."
    exit 1
fi
echo "Build succeeded."

# ── 3. TLS 인증서 생성 ───────────────────────────────
echo ""
echo "--- [3/6] Generating TLS Certificates ---"

sudo mkdir -p /etc/renux

# server_e ↔ client_e 용 인증서
if [ ! -f /etc/renux/server.crt ]; then
    sudo openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/renux/server.key \
        -out    /etc/renux/server.crt \
        -days 730 -nodes \
        -subj "/CN=renux-server/O=Renux" 2>/dev/null
    sudo chmod 600 /etc/renux/server.key
    sudo chmod 644 /etc/renux/server.crt
    echo "  server.crt / server.key generated."
else
    echo "  Existing server cert found — skipping."
fi

# renux_master ↔ renux agent 용 인증서
if [ ! -f /etc/renux/master.crt ]; then
    sudo openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/renux/master.key \
        -out    /etc/renux/master.crt \
        -days 730 -nodes \
        -subj "/CN=renux-master/O=Renux" 2>/dev/null
    sudo chmod 600 /etc/renux/master.key
    sudo chmod 644 /etc/renux/master.crt
    echo "  master.crt / master.key generated."
else
    echo "  Existing master cert found — skipping."
fi

# ── 4. 바이너리 설치 ──────────────────────────────────
echo ""
echo "--- [4/6] Installing Binaries ---"

sudo cp renux        /usr/local/bin/renux
sudo cp renux_master /usr/local/bin/renux_master
sudo chmod +x /usr/local/bin/renux
sudo chmod +x /usr/local/bin/renux_master

# ── 4. Agent 설정 ─────────────────────────────────────
echo ""
echo "--- [5/6] Configuring Renux Agent ---"

if [ ! -f /etc/renux.conf ]; then
    read -p "Enter Master Server IP (e.g., 192.168.64.1): " master_ip
    echo "MASTER_IP=$master_ip"   | sudo tee    /etc/renux.conf > /dev/null
    echo "MASTER_PORT=9000"        | sudo tee -a /etc/renux.conf > /dev/null
    echo "Configuration saved to /etc/renux.conf"
else
    echo "Existing configuration found at /etc/renux.conf — skipping."
fi

# ── 5. systemd 서비스 등록 ────────────────────────────
echo ""
echo "--- [6/6] Registering systemd Services ---"

# Agent 서비스
sudo tee /etc/systemd/system/renux.service > /dev/null <<'EOF'
[Unit]
Description=Renux Security Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/renux
Restart=always
RestartSec=5
StandardOutput=append:/var/log/renux.log
StandardError=append:/var/log/renux.log

[Install]
WantedBy=multi-user.target
EOF

# Master 서비스
sudo tee /etc/systemd/system/renux-master.service > /dev/null <<'EOF'
[Unit]
Description=Renux Master Log Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/renux_master
Restart=always
RestartSec=5
WorkingDirectory=/var/log
StandardOutput=append:/var/log/renux-master.log
StandardError=append:/var/log/renux-master.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

# Agent 시작 여부 확인
read -p "Start Renux Agent now? [y/N]: " start_agent
if [[ "$start_agent" =~ ^[Yy]$ ]]; then
    sudo systemctl enable renux
    sudo systemctl restart renux
    echo "Agent status: $(sudo systemctl is-active renux)"
fi

# Master 시작 여부 확인
read -p "Start Renux Master Server now? [y/N]: " start_master
if [[ "$start_master" =~ ^[Yy]$ ]]; then
    sudo systemctl enable renux-master
    sudo systemctl restart renux-master
    echo "Master status: $(sudo systemctl is-active renux-master)"
fi

echo ""
echo "=================================================="
echo "  Installation Complete!"
echo "  Agent log : /var/log/renux.log"
echo "  Master log: /var/log/renux-master.log"
echo "  Config    : /etc/renux.conf"
echo "=================================================="
