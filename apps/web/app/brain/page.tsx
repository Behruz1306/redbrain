"use client";

import { useEffect, useState } from "react";
import { GraphView } from "@/components/GraphView";

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

interface KnowledgeInfo {
  total_scans: number;
  total_patterns: number;
  vuln_classes_seen: string[];
  brain_size_kb: number;
  embedding_corpus_size: number;
  gbrain_pages: number;
  gbrain_links: number;
  active_scans: number;
}

interface AgentInfo {
  name: string;
  file: string;
  description: string;
  role_content: string;
}

export default function BrainPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [search, setSearch] = useState("");
  const [knowledge, setKnowledge] = useState<KnowledgeInfo | null>(null);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [activeTab, setActiveTab] = useState<"graph" | "agents" | "knowledge">("graph");

  useEffect(() => {
    fetch("/api/brain/graph")
      .then((r) => r.json())
      .then((data) => {
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
      })
      .catch(() => {});

    fetch("/api/brain/knowledge")
      .then((r) => r.json())
      .then(setKnowledge)
      .catch(() => {});

    fetch("/api/brain/agents")
      .then((r) => r.json())
      .then((data) => setAgents(data.agents || []))
      .catch(() => {});
  }, []);

  const filteredNodes = search
    ? nodes.filter((n) => n.label.toLowerCase().includes(search.toLowerCase()))
    : nodes;

  return (
    <div className="h-screen flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-4 p-3 border-b border-[var(--color-border)]">
        <h1 className="text-sm font-bold">
          <span className="text-[var(--color-critical)]">Red</span>Brain
        </h1>

        {/* Tabs */}
        <div className="flex gap-1">
          {(["graph", "agents", "knowledge"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1 rounded text-[10px] font-medium uppercase transition-colors ${
                activeTab === tab
                  ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {activeTab === "graph" && (
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search nodes..."
            className="flex-1 max-w-md bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
          />
        )}

        <div className="ml-auto text-xs text-[var(--color-text-dim)]">
          {nodes.length} nodes | {edges.length} edges
          {knowledge && ` | ${knowledge.embedding_corpus_size} embeddings`}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "graph" && (
          <GraphView nodes={filteredNodes} edges={edges} />
        )}

        {activeTab === "knowledge" && (
          <div className="p-6 max-w-3xl mx-auto space-y-6 overflow-y-auto h-full">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold">Brain Knowledge Base</h2>
              <a
                href="/kb"
                className="px-3 py-1.5 text-[10px] font-semibold uppercase rounded bg-purple-900/30 border border-purple-700/50 text-purple-300 hover:bg-purple-900/50 transition-colors"
              >
                Explore Full KB →
              </a>
            </div>

            {knowledge ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-[var(--color-accent)]">{knowledge.total_scans}</div>
                  <div className="text-xs text-[var(--color-text-dim)]">Total Scans Completed</div>
                </div>
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-purple-400">{knowledge.total_patterns}</div>
                  <div className="text-xs text-[var(--color-text-dim)]">Vulnerability Patterns Learned</div>
                </div>
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-blue-400">{knowledge.embedding_corpus_size}</div>
                  <div className="text-xs text-[var(--color-text-dim)]">Semantic Embeddings (ZeroEntropy)</div>
                </div>
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-green-400">{knowledge.gbrain_pages}</div>
                  <div className="text-xs text-[var(--color-text-dim)]">GBrain Knowledge Pages</div>
                </div>
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-yellow-400">{knowledge.gbrain_links}</div>
                  <div className="text-xs text-[var(--color-text-dim)]">Knowledge Graph Links</div>
                </div>
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="text-3xl font-bold text-orange-400">{knowledge.brain_size_kb} KB</div>
                  <div className="text-xs text-[var(--color-text-dim)]">Persistent Brain Size</div>
                </div>
              </div>
            ) : (
              <div className="text-[var(--color-text-dim)]">Loading...</div>
            )}

            {/* KB Summary */}
            <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-3">
              <div className="text-xs font-semibold uppercase text-[var(--color-text-dim)]">Loaded Knowledge</div>
              <div className="grid grid-cols-4 gap-3 text-center">
                <div>
                  <div className="text-xl font-bold text-red-400">71</div>
                  <div className="text-[9px] text-[var(--color-text-dim)]">CVEs</div>
                </div>
                <div>
                  <div className="text-xl font-bold text-orange-400">44</div>
                  <div className="text-[9px] text-[var(--color-text-dim)]">Techniques</div>
                </div>
                <div>
                  <div className="text-xl font-bold text-green-400">16</div>
                  <div className="text-[9px] text-[var(--color-text-dim)]">Detectors</div>
                </div>
                <div>
                  <div className="text-xl font-bold text-blue-400">200+</div>
                  <div className="text-[9px] text-[var(--color-text-dim)]">Payloads</div>
                </div>
              </div>
            </div>

            {knowledge && knowledge.vuln_classes_seen.length > 0 && (
              <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                <div className="text-xs font-semibold uppercase text-[var(--color-text-dim)] mb-3">
                  Vulnerability Classes in Memory
                </div>
                <div className="flex flex-wrap gap-2">
                  {knowledge.vuln_classes_seen.map((cls) => (
                    <span key={cls} className="px-2 py-1 rounded text-[10px] bg-red-900/30 text-red-300 border border-red-800/50">
                      {cls}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "agents" && (
          <div className="p-6 max-w-3xl mx-auto space-y-6 overflow-y-auto h-full">
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold">GStack Agent Roles</h2>
              <span className="px-2 py-0.5 rounded text-[9px] bg-purple-900/50 text-purple-300 border border-purple-700">
                GStack Framework
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-dim)]">
              Each agent has a specialized role defined in .claude/commands/ following the GStack pattern.
            </p>

            <div className="space-y-3">
              {agents.map((agent) => (
                <div key={agent.name} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-sm font-bold text-[var(--color-accent)]">{agent.name}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)]">{agent.file}</span>
                  </div>
                  <pre className="text-[11px] text-[var(--color-text-dim)] whitespace-pre-wrap leading-relaxed max-h-40 overflow-y-auto">
                    {agent.role_content}
                  </pre>
                </div>
              ))}

              {agents.length === 0 && (
                <div className="text-[var(--color-text-dim)] text-xs">No agent roles found.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
