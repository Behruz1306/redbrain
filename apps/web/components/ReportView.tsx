"use client";

interface ReportStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  bounty_value: number;
}

interface ReportViewProps {
  stats: ReportStats;
  scanId: string;
}

export function ReportView({ stats, scanId }: ReportViewProps) {
  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">
        Executive Summary
      </h2>

      <div className="grid grid-cols-5 gap-4 text-center">
        <div>
          <div className="text-2xl font-bold text-[var(--color-text)]">{stats.total}</div>
          <div className="text-[10px] text-[var(--color-text-dim)] uppercase">Total</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-[var(--color-critical)]">{stats.critical}</div>
          <div className="text-[10px] text-[var(--color-text-dim)] uppercase">Critical</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-[var(--color-high)]">{stats.high}</div>
          <div className="text-[10px] text-[var(--color-text-dim)] uppercase">High</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-[var(--color-medium)]">{stats.medium}</div>
          <div className="text-[10px] text-[var(--color-text-dim)] uppercase">Medium</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-[var(--color-low)]">{stats.low}</div>
          <div className="text-[10px] text-[var(--color-text-dim)] uppercase">Low</div>
        </div>
      </div>

      <div className="text-center pt-3 border-t border-[var(--color-border)]">
        <span className="text-xs text-[var(--color-text-dim)]">Bug bounty equivalent: </span>
        <span className="text-xl font-bold text-[var(--color-accent)]">
          ~${stats.bounty_value.toLocaleString()}
        </span>
      </div>

      <div className="flex gap-3 justify-center pt-2">
        <a
          href={`/api/scan/${scanId}/report/download`}
          className="px-4 py-2 bg-[var(--color-accent)] text-[var(--color-bg)] rounded text-xs font-semibold uppercase hover:brightness-110 transition-all"
        >
          Download Report
        </a>
        <a
          href="/brain"
          className="px-4 py-2 border border-[var(--color-border)] text-[var(--color-text)] rounded text-xs font-semibold uppercase hover:border-[var(--color-accent)] transition-colors"
        >
          View Brain
        </a>
      </div>
    </div>
  );
}
