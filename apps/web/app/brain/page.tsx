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

export default function BrainPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    fetch("/api/brain/graph")
      .then((r) => r.json())
      .then((data) => {
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
      })
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
          <span className="text-[var(--color-critical)]">Red</span>Brain Graph Explorer
        </h1>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search nodes..."
          className="flex-1 max-w-md bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
        />
        <div className="text-xs text-[var(--color-text-dim)]">
          {nodes.length} nodes | {edges.length} edges
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1">
        <GraphView nodes={filteredNodes} edges={edges} />
      </div>
    </div>
  );
}
