"use client";

import { useEffect, useState, use } from "react";

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
}

const severityBadge: Record<string, string> = {
  critical: "bg-[var(--color-critical)] text-white",
  high: "bg-[var(--color-high)] text-white",
  medium: "bg-[var(--color-medium)] text-black",
  low: "bg-[var(--color-low)] text-black",
};

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);

  useEffect(() => {
    fetch(`/api/scan/${id}/report`)
      .then((r) => r.json())
      .then(setReport)
      .catch(() => {});
  }, [id]);

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
        <p className="text-xs text-[var(--color-text-dim)]">Scan ID: {id}</p>
      </div>

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
