#!/bin/bash
# ARGUS Linux Installer
# "The All-Seeing Network Eye"

echo "👁️  Installing ARGUS Dependencies..."

# 1. System Dependencies (libpcap for Scapy, venv for python)
if [ -x "$(command -v apt-get)" ]; then
    echo "[*] Installing system libraries..."
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-venv libpcap-dev
elif [ -x "$(command -v yum)" ]; then
    sudo yum install -y python3-pip libpcap-devel
fi

# 2. Virtual Environment (Critical for Kali/Debian 12+)
if [ ! -d "venv" ]; then
    echo "[*] Creating Python Virtual Environment (venv)..."
    python3 -m venv venv
fi

# 3. Python Dependencies
echo "[*] Installing Python requirements into venv..."
./venv/bin/pip install -r requirements.txt

# 4. Permissions (Raw Sockets need root)
echo "[*] Attempting to set capabilities for raw socket access..."
# Resolve the actual binary path for the venv python
VENV_PYTHON=$(readlink -f ./venv/bin/python3)
sudo setcap cap_net_raw=eip "$VENV_PYTHON" 2>/dev/null || echo "⚠️  Could not set capabilities. You may need to run as sudo."

echo ""
echo "✅ Installation Complete."
echo "--------------------------------------------------------"
echo "🚀 TO RUN ARGUS:"
echo "   1. Activate venv:    source venv/bin/activate"
echo "   2. Run Training:     sudo ./venv/bin/python3 project_alpha/main.py --train"
echo "   3. Run Detection:    sudo ./venv/bin/python3 project_alpha/main.py --detect"
echo "--------------------------------------------------------"
