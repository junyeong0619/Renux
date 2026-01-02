#!/bin/bash

echo "[*] Building project..."
make

if [ ! -f "renux" ]; then
    echo "[!] 'renux' binary not found. Compiling manually..."
    g++ -o renux monitoring/monitor.cpp -std=c++17
fi

echo "[*] Installing renux..."
if [ -f "renux" ]; then
    sudo cp renux /usr/local/bin/
    sudo chmod +x /usr/local/bin/renux
else
    echo "[X] Build failed: 'renux' executable not found."
    exit 1
fi

echo "[*] Setting up log file..."
if [ ! -f "/var/log/renux.log" ]; then
    sudo touch /var/log/renux.log
fi
sudo chmod 666 /var/log/renux.log

echo "--------------------------------------------------"
echo "Setup Complete!"
echo "1. Run Agent : renux &"
echo "2. Trace User: renux trace <username>"
echo "--------------------------------------------------"