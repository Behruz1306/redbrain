"use client";

import { useEffect, useState } from "react";
import { GraphView } from "@/components/GraphView";

interface GraphNode {
  id: string;
  label: string;
  type: string;
}

interface GraphEdge {
  source: string;
  target: string;
  type?: string;
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

interface CompoundInfo {
  brain_health: {
    total_nodes: number;
    total_edges: number;
    graph_density: number;
    embeddings: number;
    scans_processed: number;
  };
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  knowledge_layers: { name: string; count: number; status: string }[];
  compounding_factor: number;
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
  const [compound, setCompound] = useState<CompoundInfo | null>(null);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [activeTab, setActiveTab] = useState<"graph" | "agents" | "compound">("graph");

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

    fetch("/api/brain/compound")
      .then((r) => r.json())
      .then(setCompound)
      .catch(() => {});

    fetch("/api/brain/agents")
      .then((r) => r.json())
      .then((data) => setAgents(data.agents || []))
      .catch(() => {});
  }, []);

  const filteredNodes = search
    ? nodes.filter((n) => n.label.toLowerCase().includes(search.toLowerCase()) || n.type.toLowerCase().includes(search.toLowerCase()))
    : nodes;

  const filteredEdges = search
    ? edges.filter((e) => {
        const srcNode = nodes.find((n) => n.id === e.source);
        const tgtNode = nodes.find((n) => n.id === e.target);
        return (
          filteredNodes.some((n) => n.id === e.source) ||
          filteredNodes.some((n) => n.id === e.target)
        );
      })
    : edges;

  return (
    <div className="h-screen flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-4 p-3 border-b border-[var(--color-border)] bg-[var(--color-bg)]">
        <a href="/" className="text-sm font-bold">
          <span className="text-[var(--color-critical)]">Red</span>Brain
        </a>

        {/* Tabs */}
        <div className="flex gap-1">
          {([
            { id: "graph", label: "Knowledge Graph" },
            { id: "compound", label: "Compounding" },
            { id: "agents", label: "GStack Agents" },
          ] as const).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1 rounded text-[10px] font-medium uppercase tracking-wider transition-colors ${
                activeTab === tab.id
                  ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === "graph" && (
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search nodes (type or name)..."
            className="flex-1 max-w-md bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
          />
        )}

        <div className="ml-auto flex items-center gap-4 text-[10px] text-[var(--color-text-dim)]">
          {compound && (
            <span className="px-2 py-1 rounded bg-green-900/30 border border-green-800/50 text-green-400 font-bold">
              {compound.compounding_factor}x compound
            </span>
          )}
          <span>{nodes.length} nodes</span>
          <span>{edges.length} edges</span>
          {knowledge && <span>{knowledge.embedding_corpus_size} embeddings</span>}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "graph" && (
          <GraphView nodes={filteredNodes} edges={filteredEdges} />
        )}

        {activeTab === "compound" && (
          <div className="p-6 max-w-4xl mx-auto space-y-6 overflow-y-auto h-full">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold">Knowledge Compounding</h2>
                <p className="text-xs text-[var(--color-text-dim)]">
                  Each scan makes the brain smarter. Knowledge compounds through cross-references.
                </p>
              </div>
              {compound && (
                <div className="text-right">
                  <div className="text-3xl font-bold text-green-400">{compound.compounding_factor}x</div>
                  <div className="text-[9px] text-[var(--color-text-dim)] uppercase">Intelligence Factor</div>
                </div>
              )}
            </div>

            {compound && (
              <>
                {/* Brain Health Metrics */}
                <div className="grid grid-cols-5 gap-3">
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-[var(--color-accent)]">{compound.brain_health.total_nodes}</div>
                    <div className="text-[9px] text-[var(--color-text-dim)]">Nodes</div>
                  </div>
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-purple-400">{compound.brain_health.total_edges}</div>
                    <div className="text-[9px] text-[var(--color-text-dim)]">Edges</div>
                  </div>
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-blue-400">{compound.brain_health.embeddings}</div>
                    <div className="text-[9px] text-[var(--color-text-dim)]">Embeddings</div>
                  </div>
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-yellow-400">{(compound.brain_health.graph_density * 100).toFixed(1)}%</div>
                    <div className="text-[9px] text-[var(--color-text-dim)]">Density</div>
                  </div>
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-green-400">{compound.brain_health.scans_processed}</div>
                    <div className="text-[9px] text-[var(--color-text-dim)]">Scans</div>
                  </div>
                </div>

                {/* Knowledge Layers */}
                <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-5 space-y-3">
                  <div className="text-xs font-semibold uppercase text-[var(--color-text-dim)]">Knowledge Layers</div>
                  <div className="space-y-2">
                    {compound.knowledge_layers.map((layer) => (
                      <div key={layer.name} className="flex items-center gap-3">
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-[var(--color-text)]">{layer.name}</span>
                            <span className="text-[10px] text-[var(--color-text-dim)]">{layer.count} items</span>
                          </div>
                          <div className="w-full bg-[var(--color-bg)] rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full transition-all ${
                                layer.status === "loaded" ? "bg-green-500" : "bg-yellow-600"
                              }`}
                              style={{ width: `${Math.min(100, (layer.count / 80) * 100)}%` }}
                            />
                          </div>
                        </div>
                        <span className={`text-[9px] px-2 py-0.5 rounded ${
                          layer.status === "loaded"
                            ? "bg-green-900/30 text-green-400 border border-green-800/50"
                            : "bg-yellow-900/30 text-yellow-400 border border-yellow-800/50"
                        }`}>
                          {layer.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Node Type Distribution */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-3">
                    <div className="text-xs font-semibold uppercase text-[var(--color-text-dim)]">Node Types</div>
                    <div className="space-y-1.5">
                      {Object.entries(compound.node_types).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                        <div key={type} className="flex items-center justify-between text-[10px]">
                          <span className="text-[var(--color-text)]">{type}</span>
                          <span className="text-[var(--color-text-dim)] font-mono">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-3">
                    <div className="text-xs font-semibold uppercase text-[var(--color-text-dim)]">Edge Types</div>
                    <div className="space-y-1.5">
                      {Object.entries(compound.edge_types).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                        <div key={type} className="flex items-center justify-between text-[10px]">
                          <span className="text-[var(--color-text)]">{type}</span>
                          <span className="text-[var(--color-text-dim)] font-mono">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* How compounding works */}
                <div className="bg-purple-900/20 border border-purple-700/40 rounded-lg p-5 space-y-3">
                  <div className="text-xs font-semibold text-purple-300 uppercase">How Knowledge Compounding Works</div>
                  <div className="text-[11px] text-purple-200/80 space-y-2">
                    <p>Every scan adds new knowledge to the brain:</p>
                    <ul className="list-disc list-inside space-y-1 text-[10px] text-purple-300/70">
                      <li>New vulnerability patterns get embedded in ZeroEntropy for future semantic matching</li>
                      <li>Cross-links are created between new findings and existing CVEs/techniques</li>
                      <li>GBrain stores the relationship graph — each node connected to related knowledge</li>
                      <li>Future scans use the expanded brain to find more complex, chained vulnerabilities</li>
                      <li>The compounding factor grows: more knowledge = better detection = more knowledge</li>
                    </ul>
                  </div>
                </div>
              </>
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
              They orchestrate together to perform comprehensive security analysis.
            </p>

            {/* Architecture diagram */}
            <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-5 space-y-3">
              <div className="text-xs font-semibold text-[var(--color-text-dim)] uppercase">Agent Pipeline</div>
              <div className="flex items-center gap-2 overflow-x-auto py-2">
                {["Recon", "SAST", "Exploit", "Remediate", "Report"].map((stage, i) => (
                  <div key={stage} className="flex items-center gap-2">
                    <div className="px-3 py-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-[10px] font-semibold text-[var(--color-accent)] whitespace-nowrap">
                      {stage}
                    </div>
                    {i < 4 && <span className="text-[var(--color-text-dim)]">→</span>}
                  </div>
                ))}
              </div>
            </div>

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
                <div className="text-[var(--color-text-dim)] text-xs">Loading agent roles...</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
