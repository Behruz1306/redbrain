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
        message: `${payload.function_name} → ${payload.endpoint} (${((payload.confidence as number) * 100).toFixed(0)}%) [${payload.method || "heuristic"}]`,
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
  const [reasoning, setReasoning] = useState<string[]>([]);
  const [riskScore, setRiskScore] = useState<{ score: number; grade: string } | null>(null);
  const [brainContext, setBrainContext] = useState<{ prior_scans: number; known_patterns: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);

  const handleEvent = useCallback((event: ScanEvent) => {
    const stageIdx = getStageIndex(event.type);
    if (stageIdx > 0 || event.type.startsWith("sast:")) {
      setCurrentStage(stageIdx);
    }

    // Route to terminals
    const sastLog = eventToLog(event, "sast");
    if (sastLog) setSastLogs((prev) => [...prev, sastLog]);

    const dastLog = eventToLog(event, "dast");
    if (dastLog) setDastLogs((prev) => [...prev, dastLog]);

    // AI Reasoning traces
    if (event.type === "agent:reasoning") {
      const thought = `[${event.payload.agent}] ${event.payload.thought}`;
      setReasoning((prev) => [...prev.slice(-14), thought]);
      setCurrentAction(event.payload.thought as string);
    }

    // AI insights as reasoning
    if (event.type === "ai:sast_validation") {
      const thought = `[ai/sast] ${event.payload.function}: ${event.payload.ai_assessment}`;
      setReasoning((prev) => [...prev.slice(-14), thought]);
    }
    if (event.type === "ai:correlation_insight") {
      const thought = `[ai/correlate] ${event.payload.function} → ${event.payload.endpoint}: ${event.payload.insight}`;
      setReasoning((prev) => [...prev.slice(-14), thought]);
    }
    if (event.type === "ai:deep_analysis") {
      const thought = `[ai/deep] FOUND: ${event.payload.function} (${event.payload.file}) — ${event.payload.description}`;
      setReasoning((prev) => [...prev.slice(-14), thought]);
      setSastLogs((prev) => [...prev, {
        timestamp: new Date().toISOString(),
        type: "AI-DEEP",
        message: `${event.payload.function}: ${(event.payload.signals as string[])?.join(", ")} (${event.payload.confidence}% confidence)`,
        severity: "critical",
      }]);
    }
    if (event.type === "remediate:fix_generated") {
      const thought = `[ai/fix] Generated code fix for: ${event.payload.title}`;
      setReasoning((prev) => [...prev.slice(-14), thought]);
    }

    // Brain context
    if (event.type === "brain:context") {
      setBrainContext({
        prior_scans: event.payload.prior_scans as number,
        known_patterns: event.payload.known_patterns as number,
      });
    }

    // Risk score
    if (event.type === "ai:risk_score") {
      setRiskScore({
        score: event.payload.score as number,
        grade: event.payload.grade as string,
      });
    }

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
    } else if (event.type === "ai:attack_chains") {
      setCurrentAction(`Found ${event.payload.total} attack chains`);
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
      if (event.payload.risk_grade) {
        setRiskScore({
          score: event.payload.risk_score as number,
          grade: event.payload.risk_grade as string,
        });
      }
      setTimeout(() => router.push(`/scan/${id}/report`), 2000);
    }
  }, [id, router]);

  useEffect(() => {
    const ws = connectScanStream(id, handleEvent, () => {});
    return () => ws.close();
  }, [id, handleEvent]);

  // Fallback polling: check scan status every 3s, redirect to report when done
  useEffect(() => {
    const poll = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan/${id}`);
        const data = await res.json();
        if (data.status === "complete") {
          clearInterval(poll);
          router.push(`/scan/${id}/report`);
        } else if (data.status === "error") {
          clearInterval(poll);
          setError(data.error || "Scan failed");
        }
      } catch {}
    }, 3000);
    return () => clearInterval(poll);
  }, [id, router]);

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

        {/* Brain context badge */}
        {brainContext && brainContext.prior_scans > 0 && (
          <span className="ml-2 px-2 py-0.5 rounded text-[9px] bg-purple-900/50 text-purple-300 border border-purple-700">
            BRAIN: {brainContext.prior_scans} prior scans
          </span>
        )}

        {/* Risk score badge */}
        {riskScore && (
          <span className={`ml-2 px-2 py-0.5 rounded text-[9px] font-bold ${
            riskScore.grade === "F" ? "bg-red-900/50 text-red-300 border border-red-700" :
            riskScore.grade === "D" ? "bg-orange-900/50 text-orange-300 border border-orange-700" :
            riskScore.grade === "C" ? "bg-yellow-900/50 text-yellow-300 border border-yellow-700" :
            "bg-green-900/50 text-green-300 border border-green-700"
          }`}>
            RISK: {riskScore.grade} ({riskScore.score}/100)
          </span>
        )}

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

        {/* Bottom: AI reasoning + graph */}
        <div className="col-span-2 grid grid-cols-[2fr_1fr] gap-3 min-h-0">
          {/* AI Reasoning panel */}
          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-3 flex flex-col overflow-hidden">
            <div className="text-[9px] uppercase text-purple-400 tracking-wider font-semibold mb-1 flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
              AI Reasoning Trace
            </div>
            <div className="flex-1 overflow-y-auto space-y-1">
              {reasoning.length === 0 ? (
                <div className="text-xs text-[var(--color-text-dim)]">{currentAction}</div>
              ) : (
                reasoning.map((thought, i) => (
                  <div key={i} className={`text-[11px] leading-tight ${
                    i === reasoning.length - 1 ? "text-[var(--color-accent)]" : "text-[var(--color-text-dim)]"
                  }`}>
                    {thought}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Mini graph */}
          <GraphView nodes={nodes} edges={edges} />
        </div>
      </div>
    </div>
  );
}
