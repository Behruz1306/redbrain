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

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/scan/${id}/report`)
      .then((r) => r.json())
      .then(setReport)
      .catch(() => {});
  }, [id]);

  function handleCopy(vulnId: string, text: string) {
    copyToClipboard(text);
    setCopied(vulnId);
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

  return (
    <div className="min-h-screen p-6 max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold">
          <span className="text-[var(--color-critical)]">Red</span>Brain Security Report
        </h1>
        <p className="text-xs text-[var(--color-text-dim)]">Scan ID: {id} | AI-Powered Analysis</p>
      </div>

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
              <span className="text-xs text-[var(--color-text-dim)]">
                {vuln.vuln_class} | {(vuln.confidence * 100).toFixed(0)}%
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
                        {copied === vuln.id ? "Copied!" : "Copy"}
                      </button>
                    </div>

                    {/* IDE Export Buttons */}
                    <div className="flex flex-wrap gap-2 pt-2">
                      <button
                        onClick={() => handleCopy(vuln.id + "-cc", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-orange-900/30 border border-orange-700/50 text-orange-300 hover:bg-orange-900/50 transition-colors"
                      >
                        {copied === vuln.id + "-cc" ? "Copied!" : "Fix in Claude Code"}
                      </button>
                      <button
                        onClick={() => handleCopy(vuln.id + "-cursor", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-blue-900/30 border border-blue-700/50 text-blue-300 hover:bg-blue-900/50 transition-colors"
                      >
                        {copied === vuln.id + "-cursor" ? "Copied!" : "Fix in Cursor"}
                      </button>
                      <button
                        onClick={() => handleCopy(vuln.id + "-ag", generateIDEPrompt(vuln))}
                        className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-purple-900/30 border border-purple-700/50 text-purple-300 hover:bg-purple-900/50 transition-colors"
                      >
                        {copied === vuln.id + "-ag" ? "Copied!" : "Fix in Antigravity"}
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
      <div className="flex gap-3 justify-center">
        <a
          href={`/api/scan/${id}/report/download`}
          className="px-4 py-2 bg-[var(--color-accent)] text-[var(--color-bg)] rounded text-xs font-semibold uppercase"
        >
          Download HackerOne Report
        </a>
        <a
          href="/brain"
          className="px-4 py-2 border border-[var(--color-border)] text-[var(--color-text)] rounded text-xs font-semibold uppercase hover:border-[var(--color-accent)] transition-colors"
        >
          View Brain Graph
        </a>
      </div>
    </div>
  );
}
