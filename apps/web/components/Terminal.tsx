"use client";

import { useEffect, useRef } from "react";

interface LogEntry {
  timestamp: string;
  type: string;
  message: string;
  severity?: "info" | "warning" | "critical" | "success";
}

interface TerminalProps {
  title: string;
  logs: LogEntry[];
}

const severityColors: Record<string, string> = {
  info: "text-[var(--color-text-dim)]",
  warning: "text-[var(--color-medium)]",
  critical: "text-[var(--color-critical)]",
  success: "text-[var(--color-accent)]",
};

export function Terminal({ title, logs }: TerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="flex flex-col h-full bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[var(--color-border)] bg-[var(--color-surface-2)]">
        <div className="flex gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-critical)]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-medium)]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-accent)]" />
        </div>
        <span className="text-xs text-[var(--color-text-dim)] ml-2">{title}</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
        {logs.map((log, i) => (
          <div key={i} className={`terminal-line ${severityColors[log.severity || "info"]}`}>
            <span className="text-[var(--color-text-dim)] mr-2">
              {new Date(log.timestamp).toLocaleTimeString("en-US", { hour12: false })}
            </span>
            <span className="mr-2">[{log.type}]</span>
            <span>{log.message}</span>
          </div>
        ))}
        {logs.length > 0 && (
          <div className="cursor-blink text-[var(--color-accent)]" />
        )}
      </div>
    </div>
  );
}
