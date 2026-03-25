#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"
BACKEND_DIR="$PROJECT_ROOT/backend"
PORT="${1:-8000}"

# Resolve data dir BEFORE sudo so ~ expands to the real user's home
DATA_DIR="${NETMAPPER_DATA_DIR:-$HOME/.netmapper}"
mkdir -p "$DATA_DIR"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt"
fi

echo "Starting NetMapper on port $PORT (requires sudo for raw sockets)..."
echo "Data directory: $DATA_DIR"
sudo NETMAPPER_DATA_DIR="$DATA_DIR" "$VENV_DIR/bin/uvicorn" main:app \
    --host 127.0.0.1 \
    --port "$PORT" \
    --app-dir "$BACKEND_DIR"
