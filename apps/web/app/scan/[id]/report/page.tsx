"use client";

import { useEffect, useState, use } from "react";

interface RemediationData {
  fixed_code: string;
  explanation: string;
  file_path: string;
  line: number;
}

interface Vulnerability {
  id: string;
  vuln_class: string;
  severity: string;
  status: string;
  confidence: number;
  title: string;
  description: string;
  function_id?: string;
  endpoint_id?: string;
  remediation?: RemediationData | null;
}

interface RiskScore {
  score: number;
  grade: string;
  recommendation: string;
  exposure_factor: number;
}

interface AttackChain {
  description: string;
  chain_length: number;
  vulnerabilities: string[];
}

interface ReportData {
  vulnerabilities: Vulnerability[];
  report_markdown: string;
  stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    bounty_value: number;
  };
  risk_score?: RiskScore;
  attack_chains?: AttackChain[];
}

const severityBadge: Record<string, string> = {
  critical: "bg-[var(--color-critical)] text-white",
  high: "bg-[var(--color-high)] text-white",
  medium: "bg-[var(--color-medium)] text-black",
  low: "bg-[var(--color-low)] text-black",
};

const gradeColor: Record<string, string> = {
  A: "text-green-400",
  B: "text-green-300",
  C: "text-yellow-400",
  D: "text-orange-400",
  F: "text-red-400",
};

function generateIDEPrompt(vuln: Vulnerability): string {
  const r = vuln.remediation;
  if (!r || !r.fixed_code) return "";
  return `Fix a ${vuln.severity} ${vuln.vuln_class} vulnerability in ${r.file_path} at line ${r.line}.

Issue: ${vuln.title}
${vuln.description}

Replace the vulnerable code with this secure version:

\`\`\`
${r.fixed_code}
\`\`\`

Explanation: ${r.explanation}`;
}

function generateAllFixesPrompt(vulns: Vulnerability[]): string {
  const fixable = vulns.filter((v) => v.remediation?.fixed_code);
  if (fixable.length === 0) return "No fixable vulnerabilities found.";

  let prompt = `RedBrain Security Report — Fix ${fixable.length} vulnerabilities:\n\n`;
  fixable.forEach((vuln, i) => {
    const r = vuln.remediation!;
    prompt += `--- Fix ${i + 1}/${fixable.length}: ${vuln.title} [${vuln.severity.toUpperCase()}] ---\n`;
    prompt += `File: ${r.file_path}:${r.line}\n`;
    prompt += `Issue: ${vuln.description}\n`;
    prompt += `\nFixed code:\n\`\`\`\n${r.fixed_code}\n\`\`\`\n`;
    prompt += `Explanation: ${r.explanation}\n\n`;
  });
  return prompt;
}

function openInIDE(platform: "claude" | "cursor" | "vscode", prompt: string) {
  navigator.clipboard.writeText(prompt);

  if (platform === "cursor") {
    window.open("cursor://", "_blank");
  } else if (platform === "claude") {
    window.open("https://claude.ai/new", "_blank");
  } else if (platform === "vscode") {
    window.open("vscode://", "_blank");
  }
}

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [showFixBanner, setShowFixBanner] = useState(true);

  useEffect(() => {
    fetch(`/api/scan/${id}/report`)
      .then((r) => r.json())
      .then(setReport)
      .catch(() => {});
  }, [id]);

  function handleCopy(key: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  if (!report) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-[var(--color-accent)] animate-pulse">
          Generating report...
        </div>
      </div>
    );
  }

  const fixableCount = report.vulnerabilities.filter((v) => v.remediation?.fixed_code).length;

  return (
    <div className="min-h-screen p-6 max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold">
          <span className="text-[var(--color-critical)]">Red</span>Brain Security Report
        </h1>
        <p className="text-xs text-[var(--color-text-dim)]">Scan ID: {id} | AI-Powered Analysis</p>
      </div>

      {/* AI Fix Notification Banner */}
      {fixableCount > 0 && showFixBanner && (
        <div className="bg-green-900/30 border border-green-700/50 rounded-lg p-4 flex items-center gap-4 animate-fade-in">
          <div className="flex-shrink-0">
            <span className="inline-block w-3 h-3 rounded-full bg-green-400 animate-pulse"></span>
          </div>
          <div className="flex-1">
            <div className="text-sm font-semibold text-green-300">
              AI generated fixes for {fixableCount} vulnerabilities
            </div>
            <div className="text-xs text-green-400/70 mt-0.5">
              Click any vulnerability to see the fix, or use &quot;Fix All&quot; to export all fixes at once to your IDE.
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => handleCopy("fix-all", generateAllFixesPrompt(report.vulnerabilities))}
              className="px-3 py-1.5 text-[10px] font-bold uppercase rounded bg-green-700 text-white hover:bg-green-600 transition-colors"
            >
              {copied === "fix-all" ? "Copied!" : "Copy All Fixes"}
            </button>
            <button
              onClick={() => setShowFixBanner(false)}
              className="px-2 py-1 text-[10px] text-green-400/70 hover:text-green-300"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Risk Score Card */}
      {report.risk_score && (
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-dim)] mb-2">
                AI Risk Assessment
              </h2>
              <p className="text-xs text-[var(--color-text-dim)] max-w-md">
                {report.risk_score.recommendation}
              </p>
            </div>
            <div className="text-center">
              <div className={`text-5xl font-black ${gradeColor[report.risk_score.grade] || "text-gray-400"}`}>
                {report.risk_score.grade}
              </div>
              <div className="text-xs text-[var(--color-text-dim)] mt-1">
                {report.risk_score.score}/100
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Executive Summary */}
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-6 space-y-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">
          Executive Summary
        </h2>
        <div className="grid grid-cols-5 gap-4 text-center">
          <div>
            <div className="text-2xl font-bold text-[var(--color-text)]">{report.stats.total}</div>
            <div className="text-[10px] text-[var(--color-text-dim)]">TOTAL</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-[var(--color-critical)]">{report.stats.critical}</div>
            <div className="text-[10px] text-[var(--color-text-dim)]">CRITICAL</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-[var(--color-high)]">{report.stats.high}</div>
            <div className="text-[10px] text-[var(--color-text-dim)]">HIGH</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-[var(--color-medium)]">{report.stats.medium}</div>
            <div className="text-[10px] text-[var(--color-text-dim)]">MEDIUM</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-[var(--color-low)]">{report.stats.low}</div>
            <div className="text-[10px] text-[var(--color-text-dim)]">LOW</div>
          </div>
        </div>
        <div className="text-center pt-2 border-t border-[var(--color-border)]">
          <span className="text-xs text-[var(--color-text-dim)]">Bug bounty equivalent: </span>
          <span className="text-lg font-bold text-[var(--color-accent)]">
            ~${report.stats.bounty_value.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Fix All Export Panel */}
      {fixableCount > 0 && (
        <div className="bg-[var(--color-surface)] border border-green-800/40 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-green-400"></span>
            <h2 className="text-sm font-semibold text-green-400 uppercase">Export All Fixes to IDE</h2>
          </div>
          <p className="text-xs text-[var(--color-text-dim)]">
            Send all {fixableCount} AI-generated fixes directly to your coding environment. The prompt will be copied and your IDE will open.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={() => openInIDE("claude", generateAllFixesPrompt(report.vulnerabilities))}
              className="flex items-center gap-3 p-3 rounded-lg bg-orange-900/20 border border-orange-700/40 hover:border-orange-500 transition-colors text-left"
            >
              <div className="w-8 h-8 rounded-lg bg-orange-900/50 flex items-center justify-center text-orange-300 text-sm font-bold">C</div>
              <div>
                <div className="text-xs font-semibold text-orange-300">Claude Code</div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Opens claude.ai with prompt</div>
              </div>
            </button>
            <button
              onClick={() => openInIDE("cursor", generateAllFixesPrompt(report.vulnerabilities))}
              className="flex items-center gap-3 p-3 rounded-lg bg-blue-900/20 border border-blue-700/40 hover:border-blue-500 transition-colors text-left"
            >
              <div className="w-8 h-8 rounded-lg bg-blue-900/50 flex items-center justify-center text-blue-300 text-sm font-bold">Cu</div>
              <div>
                <div className="text-xs font-semibold text-blue-300">Cursor</div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Opens Cursor IDE with prompt</div>
              </div>
            </button>
            <button
              onClick={() => openInIDE("vscode", generateAllFixesPrompt(report.vulnerabilities))}
              className="flex items-center gap-3 p-3 rounded-lg bg-sky-900/20 border border-sky-700/40 hover:border-sky-500 transition-colors text-left"
            >
              <div className="w-8 h-8 rounded-lg bg-sky-900/50 flex items-center justify-center text-sky-300 text-sm font-bold">VS</div>
              <div>
                <div className="text-xs font-semibold text-sky-300">VS Code + Copilot</div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Opens VS Code with prompt</div>
              </div>
            </button>
            <button
              onClick={() => handleCopy("fix-all-prompt", generateAllFixesPrompt(report.vulnerabilities))}
              className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] hover:border-[var(--color-accent)] transition-colors text-left"
            >
              <div className="w-8 h-8 rounded-lg bg-[var(--color-surface)] flex items-center justify-center text-[var(--color-text-dim)] text-sm">CP</div>
              <div>
                <div className="text-xs font-semibold text-[var(--color-text)]">
                  {copied === "fix-all-prompt" ? "Copied!" : "Copy Prompt Only"}
                </div>
                <div className="text-[10px] text-[var(--color-text-dim)]">For any AI coding tool</div>
              </div>
            </button>
          </div>
        </div>
      )}

      {/* Attack Chains */}
      {report.attack_chains && report.attack_chains.length > 0 && (
        <div className="bg-[var(--color-surface)] border border-purple-800/50 rounded-lg p-6 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-purple-400" />
            AI-Detected Attack Chains
          </h2>
          <p className="text-xs text-[var(--color-text-dim)]">
            Vulnerabilities that can be chained together for escalated impact:
          </p>
          <div className="space-y-2">
            {report.attack_chains.slice(0, 5).map((chain, i) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded bg-purple-900/20 border border-purple-800/30">
                <span className="text-[10px] font-bold text-purple-300 w-5">{i + 1}.</span>
                <span className="text-xs text-[var(--color-text)] flex-1">{chain.description}</span>
                <span className="text-[10px] text-purple-400">
                  {chain.chain_length} steps
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerabilities */}
      <div className="space-y-3">
        {report.vulnerabilities.map((vuln) => (
          <div
            key={vuln.id}
            className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden"
          >
            <button
              onClick={() => setExpanded(expanded === vuln.id ? null : vuln.id)}
              className="w-full flex items-center gap-3 p-4 text-left hover:bg-[var(--color-surface-2)] transition-colors"
            >
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${severityBadge[vuln.severity]}`}
              >
                {vuln.severity}
              </span>
              <span className="text-sm font-medium flex-1">{vuln.title}</span>
              {vuln.remediation?.fixed_code && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-green-900/30 text-green-400 border border-green-800/50">
                  FIX
                </span>
              )}
              <span className={`text-xs ${
                vuln.confidence >= 0.8 ? "text-red-400" :
                vuln.confidence >= 0.6 ? "text-orange-400" :
                "text-[var(--color-text-dim)]"
              }`}>
                {vuln.vuln_class} | {(vuln.confidence * 100).toFixed(0)}% conf
              </span>
              <span className="text-[var(--color-text-dim)]">
                {expanded === vuln.id ? "▼" : "▶"}
              </span>
            </button>

            {expanded === vuln.id && (
              <div className="border-t border-[var(--color-border)] p-4 space-y-4 animate-fade-in">
                <p className="text-xs text-[var(--color-text-dim)]">{vuln.description}</p>
                <div className="text-[10px] text-[var(--color-text-dim)]">
                  Status: <span className="text-[var(--color-accent)]">{vuln.status}</span>
                </div>

                {/* AI Code Fix */}
                {vuln.remediation && vuln.remediation.fixed_code && (
                  <div className="mt-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="inline-block w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                      <h4 className="text-xs font-semibold text-green-400 uppercase">AI-Generated Fix</h4>
                    </div>
                    <p className="text-xs text-[var(--color-text-dim)]">{vuln.remediation.explanation}</p>
                    <div className="text-[10px] text-[var(--color-text-dim)]">
                      {vuln.remediation.file_path}:{vuln.remediation.line}
                    </div>
                    <div className="relative">
                      <pre className="bg-[var(--color-bg)] border border-[var(--color-border)] rounded p-3 text-xs overflow-x-auto max-h-64">
                        <code>{vuln.remediation.fixed_code}</code>
                      </pre>
                      <button
                        onClick={() => handleCopy(vuln.id, vuln.remediation!.fixed_code)}
                        className="absolute top-2 right-2 px-2 py-1 text-[10px] bg-[var(--color-surface)] border border-[var(--color-border)] rounded hover:border-[var(--color-accent)] transition-colors"
                      >
                        {copied === vuln.id ? "Copied!" : "Copy Code"}
                      </button>
                    </div>

                    {/* IDE Export Buttons */}
                    <div className="flex flex-wrap gap-2 pt-2">
                      <button
                        onClick={() => openInIDE("claude", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-orange-900/30 border border-orange-700/50 text-orange-300 hover:bg-orange-900/50 transition-colors"
                      >
                        Fix in Claude Code
                      </button>
                      <button
                        onClick={() => openInIDE("cursor", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-blue-900/30 border border-blue-700/50 text-blue-300 hover:bg-blue-900/50 transition-colors"
                      >
                        Fix in Cursor
                      </button>
                      <button
                        onClick={() => openInIDE("vscode", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-sky-900/30 border border-sky-700/50 text-sky-300 hover:bg-sky-900/50 transition-colors"
                      >
                        Fix in VS Code
                      </button>
                      <button
                        onClick={() => handleCopy(vuln.id + "-prompt", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)] hover:border-[var(--color-accent)] transition-colors"
                      >
                        {copied === vuln.id + "-prompt" ? "Copied!" : "Copy Prompt"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="flex gap-3 justify-center flex-wrap">
        <a
          href={`/api/scan/${id}/report/download`}
          className="px-4 py-2 bg-[var(--color-accent)] text-[var(--color-bg)] rounded text-xs font-semibold uppercase"
        >
          Download Report
        </a>
        <a
          href="/brain"
          className="px-4 py-2 border border-[var(--color-border)] text-[var(--color-text)] rounded text-xs font-semibold uppercase hover:border-[var(--color-accent)] transition-colors"
        >
          Brain Graph
        </a>
        <a
          href="/developers"
          className="px-4 py-2 border border-purple-700/50 text-purple-300 rounded text-xs font-semibold uppercase hover:border-purple-500 transition-colors"
        >
          API / MCP Integration
        </a>
      </div>
    </div>
  );
}
