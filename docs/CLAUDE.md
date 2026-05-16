# RedBrain — Development Guide

## What is this
RedBrain is an autonomous AI security engineer that combines SAST + DAST + threat intel
through a knowledge graph (GBrain). It scans repos statically, attacks deployed apps
dynamically, and correlates findings into a unified brain.

## Architecture
- `apps/api/` — FastAPI backend (Python 3.12)
- `apps/web/` — Next.js 15 frontend (React 19, TypeScript)
- `.claude/commands/` — GStack role definitions for each agent

## Running locally
```bash
# Start target
cd targets && docker compose up -d

# Start backend
cd apps/api && uvicorn main:app --reload --port 8000

# Start frontend
cd apps/web && bun install && bun run dev
```

## Key patterns
- Event-driven: all agents emit events to EventBus → WebSocket → frontend
- Parallel execution: SAST + Recon run simultaneously
- Correlation layer: connects static findings to dynamic endpoints
- GStack roles: each agent has a persona in .claude/commands/

## Demo target
OWASP Juice Shop (Node.js, intentionally vulnerable)
- GitHub: https://github.com/juice-shop/juice-shop
- Local: http://localhost:3000
