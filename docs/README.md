# RedBrain

> Autonomous AI security engineer. SAST + DAST + threat intel in one brain.

RedBrain does in 90 seconds what takes a human security engineer a week: reads source code
statically, attacks the running application dynamically, and connects both through a
knowledge graph that makes every scan smarter than the last.

## The Innovation

**Correlation layer between SAST and DAST through a typed knowledge graph.**

No existing tool connects static code analysis to dynamic exploitation. Snyk doesn't
know what Burp found. Burp doesn't know what's in the code. RedBrain is the first
product that links a Function in code → Endpoint in runtime → CVE in threat intel.

## How It Works

1. **SAST Agent** — Clones repo, parses every function, runs 6 vulnerability pattern
   detectors, embeds code for similarity search
2. **Recon Agent** — Crawls the live app, discovers endpoints, fingerprints the stack
3. **Correlate Agent** — Connects functions to endpoints via name matching, parameter
   overlap, and code reference analysis
4. **Exploit Agent** — Crafts targeted payloads based on correlation data, executes
   against live endpoints
5. **Report Agent** — Generates HackerOne-quality report with three-layer evidence
   (code → exploit → CVE)

## Quick Start

```bash
# Start demo target (OWASP Juice Shop)
cd targets && docker compose up -d

# Install & run
pip install -e .
cd apps/web && bun install

# Launch
./scripts/run_demo.sh
```

Open http://localhost:3001, enter the GitHub URL and deployed URL, hit Start Scan.

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Playwright, tree-sitter
- **Frontend:** Next.js 15, React 19, Cytoscape.js, Tailwind CSS 4
- **AI:** Claude Sonnet 4.6 (Anthropic API)
- **Knowledge Graph:** GBrain managed service
- **Embeddings:** ZeroEntropy (zembed-1, zerank-2)

## Architecture

```
Frontend (Next.js) → WebSocket → FastAPI Orchestrator
                                    ├── SAST Agent
                                    ├── Recon Agent
                                    ├── Correlate Agent
                                    ├── Exploit Agent
                                    └── Report Agent
                                         ↕
                                  GBrain Knowledge Graph
```
