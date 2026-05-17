"use client";

import { useEffect, useState } from "react";

interface CVE {
  id: string;
  description: string;
  cvss_score: number;
  cwe: string;
  poc_code: string;
  affected_products: string[];
  class: string;
}

interface Technique {
  name: string;
  class: string;
  payloads: string[];
  detection_signatures: string[];
}

interface Detector {
  name: string;
  id: string;
  category: string;
}

interface KBData {
  cves: CVE[];
  techniques: Technique[];
  detectors: Detector[];
  stats: {
    total_cves: number;
    total_techniques: number;
    total_detectors: number;
    vuln_classes: string[];
    total_payloads: number;
  };
}

const classColors: Record<string, string> = {
  sqli: "text-red-400 border-red-800/50 bg-red-900/20",
  xss: "text-orange-400 border-orange-800/50 bg-orange-900/20",
  ssrf: "text-blue-400 border-blue-800/50 bg-blue-900/20",
  broken_auth: "text-yellow-400 border-yellow-800/50 bg-yellow-900/20",
  info_disclosure: "text-cyan-400 border-cyan-800/50 bg-cyan-900/20",
  command_injection: "text-red-300 border-red-800/50 bg-red-900/20",
  prototype_pollution: "text-purple-400 border-purple-800/50 bg-purple-900/20",
  ssti: "text-pink-400 border-pink-800/50 bg-pink-900/20",
  nosql_injection: "text-amber-400 border-amber-800/50 bg-amber-900/20",
  path_traversal: "text-green-400 border-green-800/50 bg-green-900/20",
  unsafe_deserialization: "text-rose-400 border-rose-800/50 bg-rose-900/20",
  race_condition: "text-indigo-400 border-indigo-800/50 bg-indigo-900/20",
  mass_assignment: "text-teal-400 border-teal-800/50 bg-teal-900/20",
  insecure_crypto: "text-violet-400 border-violet-800/50 bg-violet-900/20",
  open_redirect: "text-lime-400 border-lime-800/50 bg-lime-900/20",
  idor: "text-emerald-400 border-emerald-800/50 bg-emerald-900/20",
};

function getClassColor(cls: string): string {
  return classColors[cls] || "text-gray-400 border-gray-700 bg-gray-900/20";
}

export default function KBPage() {
  const [kb, setKb] = useState<KBData | null>(null);
  const [tab, setTab] = useState<"cves" | "techniques" | "detectors">("cves");
  const [search, setSearch] = useState("");
  const [classFilter, setClassFilter] = useState<string>("");
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [expandedTech, setExpandedTech] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/brain/kb")
      .then((r) => r.json())
      .then(setKb)
      .catch(() => {});
  }, []);

  if (!kb) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-[var(--color-accent)] animate-pulse">Loading Knowledge Base...</div>
      </div>
    );
  }

  const filteredCves = kb.cves.filter((c) => {
    const matchSearch = !search || c.id.toLowerCase().includes(search.toLowerCase()) || c.description.toLowerCase().includes(search.toLowerCase());
    const matchClass = !classFilter || c.class === classFilter;
    return matchSearch && matchClass;
  });

  const filteredTechniques = kb.techniques.filter((t) => {
    const matchSearch = !search || t.name.toLowerCase().includes(search.toLowerCase());
    const matchClass = !classFilter || t.class === classFilter;
    return matchSearch && matchClass;
  });

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <div className="border-b border-[var(--color-border)] p-4">
        <div className="max-w-6xl mx-auto flex items-center gap-4">
          <a href="/" className="text-sm font-bold">
            <span className="text-[var(--color-critical)]">Red</span>Brain
          </a>
          <h1 className="text-sm font-semibold text-[var(--color-text-dim)]">Knowledge Base</h1>
          <div className="ml-auto flex gap-3 text-xs text-[var(--color-text-dim)]">
            <span><span className="text-[var(--color-text)] font-bold">{kb.stats.total_cves}</span> CVEs</span>
            <span><span className="text-[var(--color-text)] font-bold">{kb.stats.total_techniques}</span> Techniques</span>
            <span><span className="text-[var(--color-text)] font-bold">{kb.stats.total_payloads}</span> Payloads</span>
            <span><span className="text-[var(--color-text)] font-bold">{kb.stats.total_detectors}</span> Detectors</span>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="border-b border-[var(--color-border)] p-3">
        <div className="max-w-6xl mx-auto flex items-center gap-3">
          {/* Tabs */}
          <div className="flex gap-1">
            {(["cves", "techniques", "detectors"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3 py-1.5 rounded text-[10px] font-semibold uppercase transition-colors ${
                  tab === t
                    ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                    : "bg-[var(--color-surface)] text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
                }`}
              >
                {t === "cves" ? `CVEs (${kb.stats.total_cves})` : t === "techniques" ? `Techniques (${kb.stats.total_techniques})` : `Detectors (${kb.stats.total_detectors})`}
              </button>
            ))}
          </div>

          {/* Search */}
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search..."
            className="flex-1 max-w-sm bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
          />

          {/* Class Filter */}
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] focus:outline-none focus:border-[var(--color-accent)]"
          >
            <option value="">All Classes</option>
            {kb.stats.vuln_classes.map((cls) => (
              <option key={cls} value={cls}>{cls.replace(/_/g, " ")}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="max-w-6xl mx-auto">
          {/* CVEs Tab */}
          {tab === "cves" && (
            <div className="space-y-2">
              {filteredCves.map((cve) => (
                <div key={cve.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button
                    onClick={() => setExpandedCve(expandedCve === cve.id ? null : cve.id)}
                    className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-surface-2)] transition-colors"
                  >
                    <span className="text-xs font-mono font-bold text-[var(--color-accent)] w-36 shrink-0">{cve.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${getClassColor(cve.class)}`}>
                      {cve.class.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs text-[var(--color-text)] flex-1 truncate">{cve.description.slice(0, 80)}</span>
                    <span className={`text-xs font-bold ${cve.cvss_score >= 9 ? "text-red-400" : cve.cvss_score >= 7 ? "text-orange-400" : "text-yellow-400"}`}>
                      {cve.cvss_score}
                    </span>
                    <span className="text-[var(--color-text-dim)]">{expandedCve === cve.id ? "▼" : "▶"}</span>
                  </button>
                  {expandedCve === cve.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{cve.description}</p>
                      <div className="grid grid-cols-2 gap-3 text-[10px]">
                        <div>
                          <span className="text-[var(--color-text-dim)]">CWE: </span>
                          <span className="text-[var(--color-text)]">{cve.cwe}</span>
                        </div>
                        <div>
                          <span className="text-[var(--color-text-dim)]">CVSS: </span>
                          <span className="text-[var(--color-text)] font-bold">{cve.cvss_score}</span>
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">Affected:</div>
                        <div className="flex flex-wrap gap-1">
                          {cve.affected_products.map((p, i) => (
                            <span key={i} className="px-2 py-0.5 rounded text-[9px] bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-dim)]">
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">PoC:</div>
                        <pre className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-2 text-[10px] text-green-400 overflow-x-auto">
                          {cve.poc_code}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {filteredCves.length === 0 && (
                <div className="text-center text-[var(--color-text-dim)] py-8">No CVEs match your filter.</div>
              )}
            </div>
          )}

          {/* Techniques Tab */}
          {tab === "techniques" && (
            <div className="space-y-2">
              {filteredTechniques.map((tech) => (
                <div key={tech.name} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button
                    onClick={() => setExpandedTech(expandedTech === tech.name ? null : tech.name)}
                    className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-surface-2)] transition-colors"
                  >
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${getClassColor(tech.class)}`}>
                      {tech.class.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{tech.name.replace(/_/g, " ")}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)]">{tech.payloads.length} payloads</span>
                    <span className="text-[var(--color-text-dim)]">{expandedTech === tech.name ? "▼" : "▶"}</span>
                  </button>
                  {expandedTech === tech.name && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Payloads:</div>
                        <div className="space-y-1">
                          {tech.payloads.map((p, i) => (
                            <pre key={i} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-2 py-1 text-[10px] text-green-400 overflow-x-auto">
                              {p}
                            </pre>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">Detection:</div>
                        <div className="flex flex-wrap gap-1">
                          {tech.detection_signatures.map((s, i) => (
                            <span key={i} className="px-2 py-0.5 rounded text-[9px] bg-yellow-900/20 border border-yellow-800/50 text-yellow-400">
                              {s}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {filteredTechniques.length === 0 && (
                <div className="text-center text-[var(--color-text-dim)] py-8">No techniques match your filter.</div>
              )}
            </div>
          )}

          {/* Detectors Tab */}
          {tab === "detectors" && (
            <div className="grid grid-cols-2 gap-3">
              {kb.detectors.map((d) => (
                <div key={d.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="inline-block w-2 h-2 rounded-full bg-green-400"></span>
                    <span className="text-xs font-semibold text-[var(--color-text)]">{d.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] px-2 py-0.5 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)]">
                      {d.category}
                    </span>
                    <span className="text-[9px] text-[var(--color-text-dim)] font-mono">{d.id}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
