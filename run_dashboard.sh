#!/bin/bash
# ARGUS Dashboard Launcher

if [ ! -d "venv" ]; then
    echo "⚠️  Virtual Environment not found! Please run install.sh first."
    exit 1
fi

echo "👁️  Launching ARGUS Command Center..."
source venv/bin/activate
streamlit run dashboard.py
