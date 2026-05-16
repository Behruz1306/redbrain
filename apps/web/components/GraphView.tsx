"use client";

import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

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

interface GraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const nodeColors: Record<string, string> = {
  function: "#64748b",
  endpoint: "#3b82f6",
  vulnerability: "#ef4444",
  cve: "#eab308",
  exploit: "#f97316",
};

const nodeShapes: Record<string, string> = {
  function: "ellipse",
  endpoint: "rectangle",
  vulnerability: "triangle",
  cve: "diamond",
  exploit: "star",
};

export function GraphView({ nodes, edges }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": "8px",
            "font-family": "JetBrains Mono, monospace",
            color: "#e2e8f0",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "background-color": "data(color)",
            shape: "data(shape)" as any,
            width: 20,
            height: 20,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#334155",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "6px",
            color: "#475569",
          },
        },
      ],
      layout: { name: "cose", animate: true, animationDuration: 500 },
      userZoomingEnabled: true,
      userPanningEnabled: true,
    });

    cyRef.current = cy;
    return () => cy.destroy();
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Add new nodes
    for (const node of nodes) {
      if (!cy.getElementById(node.id).length) {
        cy.add({
          group: "nodes",
          data: {
            id: node.id,
            label: node.label.slice(0, 20),
            color: nodeColors[node.type] || "#64748b",
            shape: nodeShapes[node.type] || "ellipse",
          },
        });
      }
    }

    // Add new edges
    for (const edge of edges) {
      const edgeId = `${edge.source}-${edge.target}`;
      if (!cy.getElementById(edgeId).length) {
        if (cy.getElementById(edge.source).length && cy.getElementById(edge.target).length) {
          cy.add({
            group: "edges",
            data: {
              id: edgeId,
              source: edge.source,
              target: edge.target,
              label: edge.label || "",
            },
          });
        }
      }
    }

    cy.layout({ name: "cose", animate: true, animationDuration: 300 }).run();
  }, [nodes, edges]);

  return (
    <div className="h-full w-full bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden relative">
      <div className="absolute top-2 left-3 text-xs text-[var(--color-text-dim)] z-10">
        BRAIN GRAPH
      </div>
      <div className="absolute top-2 right-3 flex gap-3 text-[8px] z-10">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-[#64748b]" /> Function
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-[#3b82f6]" /> Endpoint
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-[#ef4444]" style={{ clipPath: "polygon(50% 0%, 0% 100%, 100% 100%)" }} /> Vuln
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-[#eab308] rotate-45" /> CVE
        </span>
      </div>
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
}
