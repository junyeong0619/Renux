#!/bin/bash

echo "--- Compiling Renux Agent ---"

if [ -f /opt/rh/devtoolset-9/enable ]; then
    source /opt/rh/devtoolset-9/enable
fi

make clean
make

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed. Please check your GCC version (C++17 support required)."
    exit 1
fi

echo "--- Installing Binary to /usr/local/bin ---"
sudo cp renux /usr/local/bin/renux
sudo chmod +x /usr/local/bin/renux


if [ ! -f /etc/renux.conf ]; then
    echo "--- Configuring Renux Agent ---"
    read -p "Enter Master Server IP (e.g., 192.168.64.1): " master_ip
    echo "MASTER_IP=$master_ip" | sudo tee /etc/renux.conf
    echo "MASTER_PORT=9000" | sudo tee -a /etc/renux.conf
    echo "✅ Configuration saved to /etc/renux.conf"
else
    echo "ℹ️ Existing configuration found at /etc/renux.conf"
fi

echo "--- Registering Renux as a System Service ---"
sudo tee /etc/systemd/system/renux.service > /dev/null <<EOF
[Unit]
Description=Renux Security Monitoring Agent
After=network.target

[Service]
Type=simple
# 서비스 실행 시 필요한 환경변수(devtoolset 등)가 있다면 여기에 추가 가능
ExecStart=/usr/local/bin/renux
Restart=always
RestartSec=5
# 로그는 기존 파일(/var/log/renux.log)에 누적
StandardOutput=append:/var/log/renux.log
StandardError=append:/var/log/renux.log

[Install]
WantedBy=multi-user.target
EOF

echo "--- Starting Renux Service ---"
sudo systemctl daemon-reload
sudo systemctl enable renux
sudo systemctl restart renux

echo "------------------------------------------------"
echo "✅ Renux Agent Installation & Service Registration Complete!"
echo "   Status: \$(sudo systemctl is-active renux)"
echo "   Log: /var/log/renux.log"
echo "------------------------------------------------"

sudo systemctl status renux --no-pager