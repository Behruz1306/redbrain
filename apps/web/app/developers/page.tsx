"use client";

import { useState } from "react";

export default function DevelopersPage() {
  const [copied, setCopied] = useState<string | null>(null);

  function copy(key: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  const apiBase = typeof window !== "undefined" ? window.location.origin : "https://benjamin11133-redbrain.hf.space";

  const mcpConfig = `{
  "mcpServers": {
    "redbrain": {
      "url": "${apiBase}/api/v1/mcp/manifest",
      "transport": "http"
    }
  }
}`;

  const curlExample = `curl -X POST ${apiBase}/api/v1/check \\
  -H "Content-Type: application/json" \\
  -d '{
    "code": "app.get(\\"/user\\", (req, res) => { db.query(\\"SELECT * FROM users WHERE id = \\" + req.params.id) })",
    "language": "javascript",
    "file_path": "routes/user.js"
  }'`;

  const pythonExample = `import httpx

response = httpx.post("${apiBase}/api/v1/check", json={
    "code": open("my_file.py").read(),
    "language": "python",
    "file_path": "my_file.py",
})
result = response.json()
for vuln in result["vulnerabilities"]:
    print(f"[{vuln['severity']}] {vuln['message']}")`;

  const vsCodeSettings = `// .vscode/settings.json — add RedBrain as MCP server
{
  "mcp": {
    "servers": {
      "redbrain": {
        "url": "${apiBase}/api/v1/mcp/manifest"
      }
    }
  }
}`;

  const claudeCodeConfig = `// Add to .claude/settings.json
{
  "mcpServers": {
    "redbrain": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "${apiBase}/api/v1/mcp/manifest"]
    }
  }
}`;

  return (
    <div className="min-h-screen p-6 max-w-4xl mx-auto space-y-10">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <a href="/" className="text-sm font-bold">
            <span className="text-[var(--color-critical)]">Red</span>Brain
          </a>
          <span className="text-[var(--color-text-dim)]">/</span>
          <span className="text-sm font-semibold">Developers</span>
        </div>
        <h1 className="text-2xl font-bold text-[var(--color-text)]">Integrate RedBrain into Your Workflow</h1>
        <p className="text-sm text-[var(--color-text-dim)]">
          Use our API or MCP server to get real-time security analysis while you code.
          Works with Claude Code, Cursor, VS Code, Windsurf, and any AI coding tool.
        </p>
      </div>

      {/* Integration Methods */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[var(--color-surface)] border border-orange-800/40 rounded-lg p-5 space-y-2">
          <div className="text-sm font-bold text-orange-300">MCP Server</div>
          <p className="text-[10px] text-[var(--color-text-dim)]">
            Connect via Model Context Protocol. Works with Claude Code, Cursor, Windsurf, etc.
          </p>
          <span className="inline-block px-2 py-0.5 text-[9px] rounded bg-orange-900/30 text-orange-400 border border-orange-800/50">
            Recommended
          </span>
        </div>
        <div className="bg-[var(--color-surface)] border border-blue-800/40 rounded-lg p-5 space-y-2">
          <div className="text-sm font-bold text-blue-300">REST API</div>
          <p className="text-[10px] text-[var(--color-text-dim)]">
            POST code to /api/v1/check and get instant vulnerability analysis back.
          </p>
          <span className="inline-block px-2 py-0.5 text-[9px] rounded bg-blue-900/30 text-blue-400 border border-blue-800/50">
            Universal
          </span>
        </div>
        <div className="bg-[var(--color-surface)] border border-green-800/40 rounded-lg p-5 space-y-2">
          <div className="text-sm font-bold text-green-300">CI/CD Hook</div>
          <p className="text-[10px] text-[var(--color-text-dim)]">
            Add to GitHub Actions, GitLab CI, or any pipeline for pre-merge security gates.
          </p>
          <span className="inline-block px-2 py-0.5 text-[9px] rounded bg-green-900/30 text-green-400 border border-green-800/50">
            Automation
          </span>
        </div>
      </div>

      {/* MCP Setup */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold flex items-center gap-2">
          <span className="inline-block w-3 h-3 rounded-full bg-orange-400"></span>
          MCP Server Setup
        </h2>
        <p className="text-xs text-[var(--color-text-dim)]">
          The MCP (Model Context Protocol) allows AI coding assistants to call RedBrain's security scanner in real-time as you write code.
        </p>

        <div className="space-y-3">
          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-orange-300">Claude Code</span>
              <button onClick={() => copy("claude-mcp", claudeCodeConfig)} className="text-[10px] text-[var(--color-text-dim)] hover:text-[var(--color-accent)]">
                {copied === "claude-mcp" ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="text-[11px] text-green-400 overflow-x-auto">{claudeCodeConfig}</pre>
          </div>

          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-blue-300">Cursor / VS Code</span>
              <button onClick={() => copy("vscode-mcp", vsCodeSettings)} className="text-[10px] text-[var(--color-text-dim)] hover:text-[var(--color-accent)]">
                {copied === "vscode-mcp" ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="text-[11px] text-green-400 overflow-x-auto">{vsCodeSettings}</pre>
          </div>

          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-purple-300">Generic MCP Config</span>
              <button onClick={() => copy("generic-mcp", mcpConfig)} className="text-[10px] text-[var(--color-text-dim)] hover:text-[var(--color-accent)]">
                {copied === "generic-mcp" ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="text-[11px] text-green-400 overflow-x-auto">{mcpConfig}</pre>
          </div>
        </div>
      </div>

      {/* API Usage */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold flex items-center gap-2">
          <span className="inline-block w-3 h-3 rounded-full bg-blue-400"></span>
          REST API
        </h2>

        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-[var(--color-text)]">POST /api/v1/check</span>
            <span className="text-[9px] text-[var(--color-text-dim)]">Real-time code analysis</span>
          </div>
          <div className="text-[10px] text-[var(--color-text-dim)] mb-3 space-y-1">
            <div><span className="text-[var(--color-text)]">code</span> (string, required) — source code to analyze</div>
            <div><span className="text-[var(--color-text)]">language</span> (string) — javascript | typescript | python</div>
            <div><span className="text-[var(--color-text)]">file_path</span> (string) — optional file path for context</div>
          </div>
          <div className="text-[10px] text-[var(--color-text-dim)]">Response: <code className="text-green-400">{"{"} vulnerabilities: [...], risk_level, suggestions {"}"}</code></div>
        </div>

        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-yellow-300">cURL Example</span>
            <button onClick={() => copy("curl", curlExample)} className="text-[10px] text-[var(--color-text-dim)] hover:text-[var(--color-accent)]">
              {copied === "curl" ? "Copied!" : "Copy"}
            </button>
          </div>
          <pre className="text-[11px] text-green-400 overflow-x-auto whitespace-pre-wrap">{curlExample}</pre>
        </div>

        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-blue-300">Python Example</span>
            <button onClick={() => copy("python", pythonExample)} className="text-[10px] text-[var(--color-text-dim)] hover:text-[var(--color-accent)]">
              {copied === "python" ? "Copied!" : "Copy"}
            </button>
          </div>
          <pre className="text-[11px] text-green-400 overflow-x-auto whitespace-pre-wrap">{pythonExample}</pre>
        </div>
      </div>

      {/* Available Tools */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold">MCP Tools Available</h2>
        <div className="space-y-2">
          {[
            { name: "check_code", desc: "Analyze code snippet for vulnerabilities in real-time", badge: "16 detectors" },
            { name: "scan_repo", desc: "Start full SAST+DAST scan of a GitHub repository", badge: "71 CVEs" },
            { name: "get_kb", desc: "Query the knowledge base for CVEs, techniques, payloads", badge: "44 techniques" },
          ].map((tool) => (
            <div key={tool.name} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 flex items-center gap-4">
              <code className="text-xs text-[var(--color-accent)] font-bold">{tool.name}</code>
              <span className="text-xs text-[var(--color-text-dim)] flex-1">{tool.desc}</span>
              <span className="text-[9px] px-2 py-0.5 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)]">
                {tool.badge}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Endpoint */}
      <div className="bg-purple-900/20 border border-purple-700/40 rounded-lg p-5 space-y-2">
        <div className="text-xs font-semibold text-purple-300 uppercase">Your RedBrain Endpoint</div>
        <div className="flex items-center gap-3">
          <code className="text-sm text-[var(--color-text)] bg-[var(--color-bg)] px-3 py-1.5 rounded border border-[var(--color-border)] flex-1">
            {apiBase}
          </code>
          <button
            onClick={() => copy("endpoint", apiBase)}
            className="px-3 py-1.5 text-xs font-semibold bg-purple-700 text-white rounded hover:bg-purple-600 transition-colors"
          >
            {copied === "endpoint" ? "Copied!" : "Copy"}
          </button>
        </div>
        <p className="text-[10px] text-purple-400/70">
          Free tier — no API key required. For production use, contact us for dedicated instances.
        </p>
      </div>

      {/* Back */}
      <div className="text-center">
        <a href="/" className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)] underline underline-offset-4">
          Back to Scanner
        </a>
      </div>
    </div>
  );
}
