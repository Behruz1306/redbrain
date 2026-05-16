#!/bin/bash
set -e

echo "=== RedBrain Demo Runner ==="
echo ""

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# Start Juice Shop if not running
if ! curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo "[*] Starting Juice Shop..."
    docker compose -f targets/docker-compose.yml up -d
    echo "[*] Waiting for Juice Shop to start..."
    for i in {1..30}; do
        if curl -s http://localhost:3000 > /dev/null 2>&1; then break; fi
        sleep 1
    done
fi

echo "[*] Juice Shop ready at http://localhost:3000"

# Start backend
echo "[*] Starting RedBrain API..."
python3 -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 &
API_PID=$!

sleep 2

# Start frontend
echo "[*] Starting RedBrain Frontend..."
cd apps/web
npx next dev --port 3001 &
WEB_PID=$!
cd "$PROJECT_ROOT"

echo ""
echo "=== RedBrain is running ==="
echo "  Frontend: http://localhost:3001"
echo "  API:      http://localhost:8000"
echo "  Target:   http://localhost:3000 (Juice Shop)"
echo ""
echo "Press Ctrl+C to stop all services"

trap "kill $API_PID $WEB_PID 2>/dev/null; docker compose -f targets/docker-compose.yml down" EXIT

wait
