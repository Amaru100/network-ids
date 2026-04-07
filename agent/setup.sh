#!/bin/bash
echo "============================================================"
echo "  NIDS Agent Setup — Linux"
echo "  University of Botswana - Final Year Project"
echo "============================================================"
echo

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 is not installed."
    echo "Run: sudo apt install python3 python3-pip"
    exit 1
fi

echo "[1/2] Installing Python dependencies..."
pip3 install scapy scikit-learn pandas numpy requests joblib
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies."
    exit 1
fi

echo
echo "[2/2] Verifying model files..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$SCRIPT_DIR/model/best_model.pkl" ]; then
    echo "[ERROR] model/best_model.pkl not found!"
    echo "Make sure the model/ folder is in the same directory as this script."
    exit 1
fi

echo
echo "============================================================"
echo "  Setup complete!"
echo
echo "  To start the agent, run:"
echo "    sudo python3 nids_agent.py --agent-name MY-PC-NAME"
echo "============================================================"
