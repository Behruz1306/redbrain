#!/bin/bash
set -e

echo "=== RedBrain Demo Runner ==="
echo ""

# Start Juice Shop if not running
if ! curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo "[*] Starting Juice Shop..."
    cd targets && docker compose up -d && cd ..
    echo "[*] Waiting for Juice Shop to start..."
    sleep 5
fi

echo "[*] Juice Shop ready at http://localhost:3000"

# Start backend
echo "[*] Starting RedBrain API..."
cd apps/api
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!
cd ../..

sleep 2

# Start frontend
echo "[*] Starting RedBrain Frontend..."
cd apps/web
bun run dev &
WEB_PID=$!
cd ../..

echo ""
echo "=== RedBrain is running ==="
echo "  Frontend: http://localhost:3000"
echo "  API:      http://localhost:8000"
echo "  Target:   http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop all services"

trap "kill $API_PID $WEB_PID 2>/dev/null; docker compose -f targets/docker-compose.yml down" EXIT

wait
