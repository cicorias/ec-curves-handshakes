#!/bin/bash
# run_demo.sh - launch toy TLS server + client demo

set -e

echo "[*] Starting server..."
python3 tls_server.py &
SERVER_PID=$!

# Wait for server to come up
sleep 1

echo "[*] Starting client..."
python3 tls_client.py

# Kill server if still running
kill $SERVER_PID 2>/dev/null || true
