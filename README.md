---
title: RedBrain
emoji: 🧠
colorFrom: red
colorTo: green
sdk: docker
app_port: 7860
---

# RedBrain

**Autonomous AI security engineer that finds, exploits, and fixes vulnerabilities in your code.**

RedBrain takes a GitHub repository, analyzes the source code with 16 static analysis detectors, tests the live application with AI-generated attack payloads, and returns a full security report with confirmed exploits and ready-to-apply fixes. The entire process takes under 90 seconds.

## What It Does

RedBrain runs five specialized AI agents in parallel:

**Recon Agent** maps the application's attack surface. It discovers API endpoints, forms, authentication flows, and hidden routes using stealth techniques that bypass WAF protection (powered by Jo/Camofox).

**SAST Agent** performs deep static analysis. Sixteen pattern detectors cover SQL injection, XSS, SSRF, prototype pollution, JWT flaws, race conditions, and more. After pattern matching, Gemini performs semantic analysis to find complex logic vulnerabilities that regex cannot detect.

**Exploit Agent** takes each finding and attacks the live application. It sends real payloads, captures real responses, and confirms whether the vulnerability is actually exploitable. No false positives.

**Remediate Agent** generates secure code fixes for every confirmed vulnerability, using the context of the original code and the specific attack vector.

**Report Agent** compiles everything into a structured report with severity ratings, proof-of-concept payloads, and estimated bug bounty values.

## Knowledge Graph

RedBrain is built on a self-compounding knowledge graph containing 216 nodes and 283 edges:

| Layer | Count | Description |
|-------|-------|-------------|
| CVEs | 71 | Real vulnerabilities with working exploit code |
| Attack Techniques | 44 | Payloads and detection signatures for each technique |
| Bug Bounty Patterns | 15 | Attack playbooks from Uber, PayPal, GitLab, Shopify |
| OWASP Top 10 | 10 | Full 2021 standard with CWE mappings |
| WAF Bypasses | 12 | Techniques for Cloudflare, AWS WAF, ModSecurity |
| Cloud Security | 10 | AWS, GCP, Azure misconfigurations |
| API Security | 12 | OWASP API Top 10 2023 coverage |
| CWE Weaknesses | 25 | Common weakness enumeration nodes |
| Vulnerability Classes | 17 | Hub nodes connecting all knowledge |

Every node is cross-linked through GBrain and embedded through ZeroEntropy for semantic search. Each scan adds new knowledge, making subsequent scans more effective.

## Real-Time IDE Integration

RedBrain provides an MCP (Model Context Protocol) server that connects to AI coding tools. Add it to Claude Code, Cursor, or VS Code and get security analysis while you write code.

```json
{
  "mcpServers": {
    "redbrain": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://benjamin11133-redbrain.hf.space/api/v1/mcp/manifest"]
    }
  }
}
```

Three tools available: `check_code` (real-time analysis), `scan_repo` (full scan), `get_kb` (query knowledge base).

## REST API

```bash
curl -X POST https://benjamin11133-redbrain.hf.space/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"code": "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)", "language": "javascript"}'
```

Returns vulnerabilities with severity, type, and AI-generated fix suggestions.

## Technology Stack

| Technology | Role |
|-----------|------|
| GBrain | Self-wiring knowledge graph with typed edges between all security entities |
| ZeroEntropy | Semantic embeddings (zembed-1) and reranking (zerank-2) for vulnerability matching |
| Gemini 2.0 Flash | Deep code analysis, complex vulnerability detection, fix generation |
| GStack | Agent orchestration framework coordinating five specialized security agents |
| The Hog | Real-time threat intelligence from social listening across security forums |
| Jo/Camofox | Stealth web reconnaissance that bypasses WAF and bot detection |

## Architecture

```
GitHub Repo ──→ Clone ──→ SAST (16 detectors + Gemini deep analysis)
                              ↓
Deployed URL ──→ Recon (Camofox) ──→ Exploit (confirmed attacks)
                              ↓
                    GBrain Knowledge Graph
                    (semantic matching via ZeroEntropy)
                              ↓
                    Remediate ──→ Report
                    (AI-generated fixes)   (structured output)
```

## Scan Modes

**Full Scan (SAST + DAST):** Provide a GitHub URL and a deployed URL. RedBrain analyzes the code and attacks the live application.

**Code-Only:** Provide just a GitHub URL. RedBrain performs deep static analysis without needing a running instance.

## Live Demo

https://benjamin11133-redbrain.hf.space

## Running Locally

```bash
pip install -e .
uvicorn apps.api.main:app --port 8000
cd apps/web && npm install && npm run dev
```

Set environment variables: `GEMINI_API_KEY`, `THE_HOG_API_KEY`, `THE_HOG_API_SECRET`, `GBRAIN_API_KEY`, `ZEROENTROPY_API_KEY`.

## License

MIT
