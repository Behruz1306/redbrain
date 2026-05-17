"use client";

import { useEffect, useRef, useState } from "react";

/* eslint-disable @typescript-eslint/no-explicit-any */

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

interface GraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const nodeColors: Record<string, string> = {
  CVE: "#ef4444",
  Technique: "#f97316",
  OWASP: "#eab308",
  BugBounty: "#a855f7",
  CWE: "#06b6d4",
  VulnClass: "#22c55e",
  WAFBypass: "#ec4899",
  CloudSecurity: "#3b82f6",
  APISecurity: "#14b8a6",
  function: "#64748b",
  endpoint: "#3b82f6",
  vulnerability: "#ef4444",
  cve: "#eab308",
  exploit: "#f97316",
};

const nodeSizes: Record<string, number> = {
  VulnClass: 35,
  OWASP: 30,
  CWE: 25,
  CVE: 18,
  Technique: 20,
  BugBounty: 22,
  WAFBypass: 18,
  CloudSecurity: 20,
  APISecurity: 20,
};

export function GraphView({ nodes, edges }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!containerRef.current) return;

    let destroyed = false;

    import("cytoscape").then((mod) => {
      if (destroyed || !containerRef.current) return;
      const cytoscape = mod.default;

      const cy = cytoscape({
        container: containerRef.current,
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)",
              "font-size": "7px",
              "font-family": "monospace",
              color: "#e2e8f0",
              "text-valign": "bottom",
              "text-margin-y": 5,
              "background-color": "data(color)",
              "background-opacity": 0.85,
              width: "data(size)",
              height: "data(size)",
              "border-width": 1,
              "border-color": "data(color)",
              "border-opacity": 0.3,
            },
          },
          {
            selector: "node:selected",
            style: {
              "border-width": 3,
              "border-color": "#ffffff",
              "font-size": "9px",
              "z-index": 999,
            },
          },
          {
            selector: "edge",
            style: {
              width: 0.7,
              "line-color": "#334155",
              "line-opacity": 0.5,
              "target-arrow-color": "#475569",
              "target-arrow-shape": "triangle",
              "arrow-scale": 0.5,
              "curve-style": "bezier",
            },
          },
          {
            selector: "edge:selected",
            style: {
              width: 2,
              "line-color": "#60a5fa",
              "target-arrow-color": "#60a5fa",
              label: "data(label)",
              "font-size": "6px",
              color: "#93c5fd",
            },
          },
        ] as any,
        layout: { name: "preset" },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        minZoom: 0.1,
        maxZoom: 4,
      });

      cyRef.current = cy;
      setReady(true);
    });

    return () => {
      destroyed = true;
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !ready) return;

    cy.elements().remove();

    const nodeIds = new Set(nodes.map((n) => n.id));

    for (const node of nodes) {
      cy.add({
        group: "nodes",
        data: {
          id: node.id,
          label: node.label.length > 22 ? node.label.slice(0, 20) + ".." : node.label,
          color: nodeColors[node.type] || "#64748b",
          size: nodeSizes[node.type] || 18,
        },
      });
    }

    for (const edge of edges) {
      if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) continue;
      if (edge.source === edge.target) continue;
      const edgeId = `${edge.source}->${edge.target}-${edge.type || "link"}`;
      cy.add({
        group: "edges",
        data: {
          id: edgeId,
          source: edge.source,
          target: edge.target,
          label: edge.type || edge.label || "",
        },
      });
    }

    if (nodes.length > 0) {
      cy.layout({
        name: "cose",
        animate: false,
        nodeRepulsion: () => 5000,
        idealEdgeLength: () => 60,
        gravity: 0.3,
        numIter: 200,
        nodeDimensionsIncludeLabels: true,
      } as any).run();

      cy.fit(undefined, 30);
    }
  }, [nodes, edges, ready]);

  const legendItems = [
    { type: "VulnClass", label: "Vuln Class", color: "#22c55e" },
    { type: "OWASP", label: "OWASP", color: "#eab308" },
    { type: "CVE", label: "CVE", color: "#ef4444" },
    { type: "CWE", label: "CWE", color: "#06b6d4" },
    { type: "Technique", label: "Technique", color: "#f97316" },
    { type: "BugBounty", label: "Bug Bounty", color: "#a855f7" },
    { type: "WAFBypass", label: "WAF Bypass", color: "#ec4899" },
    { type: "CloudSecurity", label: "Cloud", color: "#3b82f6" },
    { type: "APISecurity", label: "API", color: "#14b8a6" },
  ];

  return (
    <div className="h-full w-full bg-[#0a0a0f] border border-[var(--color-border)] rounded-lg overflow-hidden relative">
      <div className="absolute top-3 left-4 z-10 space-y-1">
        <div className="text-[10px] font-bold text-[var(--color-text-dim)] uppercase tracking-wider">
          Knowledge Graph
        </div>
        <div className="text-[9px] text-[var(--color-text-dim)]">
          {nodes.length} nodes | {edges.length} edges
        </div>
      </div>
      <div className="absolute top-3 right-4 z-10 flex flex-wrap gap-2 max-w-xs">
        {legendItems
          .filter((item) => nodes.some((n) => n.type === item.type))
          .map((item) => (
            <span key={item.type} className="flex items-center gap-1 text-[8px] text-[var(--color-text-dim)]">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: item.color }} />
              {item.label}
            </span>
          ))}
      </div>
      {!ready && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-xs text-[var(--color-text-dim)] animate-pulse">Loading graph...</div>
        </div>
      )}
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
}
