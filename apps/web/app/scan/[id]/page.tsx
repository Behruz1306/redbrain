"use client";

import { useEffect, useState, useCallback, use } from "react";
import { useRouter } from "next/navigation";
import { Terminal } from "@/components/Terminal";
import { GraphView } from "@/components/GraphView";
import { connectScanStream, ScanEvent } from "@/lib/ws";

interface LogEntry {
  timestamp: string;
  type: string;
  message: string;
  severity?: "info" | "warning" | "critical" | "success";
}

interface GraphNode {
  id: string;
  label: string;
  type: "function" | "endpoint" | "vulnerability" | "cve" | "exploit";
}

interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

const STAGES = ["SAST", "Recon", "Correlate", "Exploit", "Report"];

function eventToLog(event: ScanEvent, side: "sast" | "dast"): LogEntry | null {
  const { type, timestamp, payload } = event;

  if (side === "sast") {
    if (type === "sast:file_started")
      return { timestamp, type: "SCAN", message: `Analyzing ${payload.path}`, severity: "info" };
    if (type === "sast:function_analyzed")
      return {
        timestamp,
        type: "VULN",
        message: `${payload.name} [${(payload.risk_signals as string[])?.join(", ")}]`,
        severity: "critical",
      };
    if (type === "sast:cve_match")
      return {
        timestamp,
        type: "CVE",
        message: `${payload.function_name} ~ ${payload.cve_id} (${((payload.similarity_score as number) * 100).toFixed(0)}%)`,
        severity: "warning",
      };
    if (type === "sast:complete")
      return {
        timestamp,
        type: "DONE",
        message: `${payload.total_functions} functions, ${payload.high_risk_count} high-risk`,
        severity: "success",
      };
    if (type === "correlate:link_created")
      return {
        timestamp,
        type: "LINK",
        message: `${payload.function_name} → ${payload.endpoint} (${((payload.confidence as number) * 100).toFixed(0)}%)`,
        severity: "warning",
      };
  }

  if (side === "dast") {
    if (type === "recon:page_visited")
      return { timestamp, type: "CRAWL", message: `${payload.url} [${payload.status}]`, severity: "info" };
    if (type === "recon:endpoint_found")
      return { timestamp, type: "FOUND", message: `${payload.method} ${payload.path}`, severity: "warning" };
    if (type === "recon:stack_detected")
      return {
        timestamp,
        type: "STACK",
        message: (payload.technologies as string[])?.join(", "),
        severity: "info",
      };
    if (type === "recon:complete")
      return {
        timestamp,
        type: "DONE",
        message: `${payload.endpoints_count} endpoints discovered`,
        severity: "success",
      };
    if (type === "exploit:attempt")
      return { timestamp, type: "ATTACK", message: `${payload.technique} → ${payload.endpoint}`, severity: "warning" };
    if (type === "exploit:success")
      return {
        timestamp,
        type: "PWNED",
        message: `${payload.technique} succeeded!`,
        severity: "critical",
      };
    if (type === "exploit:complete")
      return {
        timestamp,
        type: "DONE",
        message: `${payload.successful_count}/${payload.attempted_count} exploits successful`,
        severity: "success",
      };
  }

  return null;
}

function getStageIndex(eventType: string): number {
  if (eventType.startsWith("sast:")) return 0;
  if (eventType.startsWith("recon:")) return 1;
  if (eventType.startsWith("correlate:")) return 2;
  if (eventType.startsWith("exploit:")) return 3;
  if (eventType.startsWith("report:")) return 4;
  return 0;
}

export default function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [sastLogs, setSastLogs] = useState<LogEntry[]>([]);
  const [dastLogs, setDastLogs] = useState<LogEntry[]>([]);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [currentStage, setCurrentStage] = useState(0);
  const [currentAction, setCurrentAction] = useState("Initializing scan...");
  const [error, setError] = useState<string | null>(null);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);

  const handleEvent = useCallback((event: ScanEvent) => {
    const stageIdx = getStageIndex(event.type);
    setCurrentStage(stageIdx);

    // Route to terminals
    const sastLog = eventToLog(event, "sast");
    if (sastLog) setSastLogs((prev) => [...prev, sastLog]);

    const dastLog = eventToLog(event, "dast");
    if (dastLog) setDastLogs((prev) => [...prev, dastLog]);

    // Update current action
    if (event.type === "exploit:attempt") {
      setCurrentAction(
        `Trying ${event.payload.technique} on ${event.payload.endpoint}: ${(event.payload.payload as string)?.slice(0, 50)}...`
      );
    } else if (event.type === "sast:function_analyzed") {
      setCurrentAction(`Analyzing function: ${event.payload.name}`);
    } else if (event.type === "sast:cve_match") {
      setCurrentAction(`CVE match: ${event.payload.function_name} ~ ${event.payload.cve_id}`);
    } else if (event.type === "correlate:link_created") {
      setCurrentAction(`Correlating: ${event.payload.function_name} → ${event.payload.endpoint}`);
    }

    // Update graph
    if (event.type === "sast:function_analyzed") {
      setNodes((prev) => [
        ...prev,
        { id: event.payload.function_id as string, label: event.payload.name as string, type: "function" },
      ]);
    }
    if (event.type === "sast:cve_match") {
      const cveNodeId = `cve-${event.payload.cve_id}`;
      setNodes((prev) => {
        if (prev.find((n) => n.id === cveNodeId)) return prev;
        return [...prev, { id: cveNodeId, label: event.payload.cve_id as string, type: "cve" }];
      });
      setEdges((prev) => [
        ...prev,
        { source: event.payload.function_id as string, target: cveNodeId, label: "similar_to" },
      ]);
    }
    if (event.type === "recon:endpoint_found") {
      const nodeId = `ep-${event.payload.method}-${event.payload.path}`;
      setNodes((prev) => [
        ...prev,
        { id: nodeId, label: `${event.payload.method} ${event.payload.path}`, type: "endpoint" },
      ]);
    }
    if (event.type === "correlate:link_created") {
      setEdges((prev) => [
        ...prev,
        { source: event.payload.function_id as string, target: `ep-${event.payload.endpoint}`, label: "implements" },
      ]);
    }
    if (event.type === "exploit:success") {
      setNodes((prev) => [
        ...prev,
        { id: event.payload.vulnerability_id as string, label: event.payload.technique as string, type: "vulnerability" },
      ]);
    }

    // Handle errors
    if (event.type === "scan:error") {
      setError(event.payload.error as string);
      setCurrentAction(`Error: ${event.payload.error}`);
    }

    // Navigate to report on complete
    if (event.type === "scan:complete") {
      setCurrentAction("Scan complete! Generating report...");
      setTimeout(() => router.push(`/scan/${id}/report`), 1500);
    }
  }, [id, router]);

  useEffect(() => {
    const ws = connectScanStream(id, handleEvent, () => {
      if (!error) setError("Connection lost");
    });
    return () => ws.close();
  }, [id, handleEvent, error]);

  useEffect(() => {
    const timer = setInterval(() => setElapsed(Date.now() - startTime), 1000);
    return () => clearInterval(timer);
  }, [startTime]);

  return (
    <div className="h-screen flex flex-col p-3 gap-3">
      {/* Progress bar */}
      <div className="flex items-center gap-1">
        {STAGES.map((stage, i) => (
          <div key={stage} className="flex items-center gap-1">
            <div
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                i <= currentStage
                  ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-dim)]"
              }`}
            >
              {stage}
            </div>
            {i < STAGES.length - 1 && (
              <span className={`text-xs ${i < currentStage ? "text-[var(--color-accent)]" : "text-[var(--color-border)]"}`}>
                →
              </span>
            )}
          </div>
        ))}
        <span className="ml-auto text-xs text-[var(--color-text-dim)]">
          {Math.floor(elapsed / 1000)}s | scan:{id}
        </span>
      </div>

      {/* Main content */}
      <div className="flex-1 grid grid-cols-[1fr_1fr] grid-rows-[3fr_1fr] gap-3 min-h-0">
        {/* Left terminal: SAST */}
        <Terminal title="SAST — Static Analysis" logs={sastLogs} />

        {/* Right terminal: DAST */}
        <Terminal title="DAST — Dynamic Testing" logs={dastLogs} />

        {/* Bottom: current action + graph */}
        <div className="col-span-2 grid grid-cols-[2fr_1fr] gap-3 min-h-0">
          {/* Current action */}
          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 flex items-center">
            <div className="space-y-1">
              <div className="text-[10px] uppercase text-[var(--color-text-dim)] tracking-wider">
                Currently Executing
              </div>
              <div className="text-sm text-[var(--color-accent)] font-medium">
                {currentAction}
              </div>
            </div>
          </div>

          {/* Mini graph */}
          <GraphView nodes={nodes} edges={edges} />
        </div>
      </div>
    </div>
  );
}
