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

interface OWASPEntry {
  id: string;
  name: string;
  description: string;
  cwes: string[];
  vuln_classes: string[];
  prevalence: string;
  impact: string;
  prevention: string[];
}

interface BugBountyPattern {
  id: string;
  name: string;
  category: string;
  severity: string;
  bounty_range: string;
  description: string;
  steps: string[];
  detection: string[];
  platforms_found: string[];
}

interface WAFBypass {
  id: string;
  name: string;
  category: string;
  target_wafs: string[];
  description: string;
  payloads: string[];
  detection_evasion: string;
  mitigation: string;
}

interface CloudPattern {
  id: string;
  name: string;
  provider: string;
  category: string;
  severity: string;
  description: string;
  attack_vector: string;
  detection_indicators: string[];
  remediation: string;
}

interface APIPattern {
  id: string;
  name: string;
  category: string;
  owasp_api_top10: string;
  severity: string;
  description: string;
  attack_steps: string[];
  detection_patterns: string[];
  example_vulnerable_code: string;
  remediation: string;
}

interface KBData {
  cves: CVE[];
  techniques: Technique[];
  detectors: Detector[];
  owasp: OWASPEntry[];
  bugbounty: BugBountyPattern[];
  waf_bypasses: WAFBypass[];
  cloud_security: CloudPattern[];
  api_security: APIPattern[];
  stats: {
    total_cves: number;
    total_techniques: number;
    total_detectors: number;
    total_owasp: number;
    total_bugbounty: number;
    total_waf_bypasses: number;
    total_cloud_security: number;
    total_api_security: number;
    vuln_classes: string[];
    total_payloads: number;
    total_knowledge_items: number;
  };
}

type TabId = "cves" | "techniques" | "owasp" | "bugbounty" | "waf" | "cloud" | "api" | "detectors";

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
  jwt_vuln: "text-fuchsia-400 border-fuchsia-800/50 bg-fuchsia-900/20",
};

function getClassColor(cls: string): string {
  return classColors[cls] || "text-gray-400 border-gray-700 bg-gray-900/20";
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "text-red-400 bg-red-900/30 border-red-800/50",
    high: "text-orange-400 bg-orange-900/30 border-orange-800/50",
    medium: "text-yellow-400 bg-yellow-900/30 border-yellow-800/50",
    low: "text-green-400 bg-green-900/30 border-green-800/50",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${colors[severity] || colors.medium}`}>
      {severity}
    </span>
  );
}

export default function KBPage() {
  const [kb, setKb] = useState<KBData | null>(null);
  const [tab, setTab] = useState<TabId>("cves");
  const [search, setSearch] = useState("");
  const [classFilter, setClassFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<string | null>(null);

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

  const tabs: { id: TabId; label: string; count: number }[] = [
    { id: "cves", label: "CVEs", count: kb.stats.total_cves },
    { id: "techniques", label: "Techniques", count: kb.stats.total_techniques },
    { id: "owasp", label: "OWASP", count: kb.stats.total_owasp },
    { id: "bugbounty", label: "Bug Bounty", count: kb.stats.total_bugbounty },
    { id: "waf", label: "WAF Bypass", count: kb.stats.total_waf_bypasses },
    { id: "cloud", label: "Cloud", count: kb.stats.total_cloud_security },
    { id: "api", label: "API Security", count: kb.stats.total_api_security },
    { id: "detectors", label: "Detectors", count: kb.stats.total_detectors },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <div className="border-b border-[var(--color-border)] p-4">
        <div className="max-w-7xl mx-auto flex items-center gap-4">
          <a href="/" className="text-sm font-bold">
            <span className="text-[var(--color-critical)]">Red</span>Brain
          </a>
          <h1 className="text-sm font-semibold text-[var(--color-text-dim)]">Knowledge Base</h1>
          <div className="ml-auto flex gap-4 text-[10px] text-[var(--color-text-dim)]">
            <span className="px-2 py-0.5 rounded bg-green-900/30 border border-green-800/50 text-green-400 font-bold">
              {kb.stats.total_knowledge_items} total items
            </span>
            <span>{kb.stats.total_payloads} payloads</span>
          </div>
        </div>
      </div>

      {/* Tab Bar */}
      <div className="border-b border-[var(--color-border)] p-2">
        <div className="max-w-7xl mx-auto flex items-center gap-2 overflow-x-auto">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); setExpanded(null); }}
              className={`px-3 py-1.5 rounded text-[10px] font-semibold uppercase whitespace-nowrap transition-colors ${
                tab === t.id
                  ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
              }`}
            >
              {t.label} ({t.count})
            </button>
          ))}

          <div className="flex-1" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search..."
            className="max-w-xs bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-3 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="max-w-7xl mx-auto">

          {/* CVEs */}
          {tab === "cves" && (
            <div className="space-y-2">
              {kb.cves.filter((c) => !search || c.id.toLowerCase().includes(search.toLowerCase()) || c.description.toLowerCase().includes(search.toLowerCase())).map((cve) => (
                <div key={cve.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === cve.id ? null : cve.id)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <span className="text-xs font-mono font-bold text-[var(--color-accent)] w-36 shrink-0">{cve.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${getClassColor(cve.class)}`}>{cve.class}</span>
                    <span className="text-xs text-[var(--color-text)] flex-1 truncate">{cve.description.slice(0, 80)}</span>
                    <span className={`text-xs font-bold ${cve.cvss_score >= 9 ? "text-red-400" : cve.cvss_score >= 7 ? "text-orange-400" : "text-yellow-400"}`}>{cve.cvss_score}</span>
                  </button>
                  {expanded === cve.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{cve.description}</p>
                      <div className="flex gap-4 text-[10px]"><span className="text-[var(--color-text-dim)]">CWE: <span className="text-[var(--color-text)]">{cve.cwe}</span></span></div>
                      <pre className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-2 text-[10px] text-green-400 overflow-x-auto">{cve.poc_code}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Techniques */}
          {tab === "techniques" && (
            <div className="space-y-2">
              {kb.techniques.filter((t) => !search || t.name.toLowerCase().includes(search.toLowerCase())).map((tech) => (
                <div key={tech.name} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === tech.name ? null : tech.name)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${getClassColor(tech.class)}`}>{tech.class}</span>
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{tech.name.replace(/_/g, " ")}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)]">{tech.payloads.length} payloads</span>
                  </button>
                  {expanded === tech.name && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <div className="space-y-1">
                        {tech.payloads.map((p, i) => (
                          <pre key={i} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-2 py-1 text-[10px] text-green-400 overflow-x-auto">{p}</pre>
                        ))}
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {tech.detection_signatures.map((s, i) => (
                          <span key={i} className="px-2 py-0.5 rounded text-[9px] bg-yellow-900/20 border border-yellow-800/50 text-yellow-400">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* OWASP Top 10 */}
          {tab === "owasp" && (
            <div className="space-y-3">
              {kb.owasp?.filter((o) => !search || o.name.toLowerCase().includes(search.toLowerCase())).map((entry) => (
                <div key={entry.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === entry.id ? null : entry.id)} className="w-full flex items-center gap-3 p-4 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <span className="text-xs font-mono font-bold text-yellow-400 w-20 shrink-0">{entry.id}</span>
                    <span className="text-sm font-medium text-[var(--color-text)] flex-1">{entry.name}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)]">{entry.cwes.length} CWEs</span>
                  </button>
                  {expanded === entry.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-4 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{entry.description}</p>
                      <div className="grid grid-cols-2 gap-4 text-[10px]">
                        <div><span className="text-[var(--color-text-dim)]">Prevalence: </span><span className="text-[var(--color-text)]">{entry.prevalence}</span></div>
                        <div><span className="text-[var(--color-text-dim)]">Impact: </span><span className="text-[var(--color-text)]">{entry.impact}</span></div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Prevention:</div>
                        <ul className="space-y-1">
                          {entry.prevention.map((p, i) => (
                            <li key={i} className="text-[10px] text-green-400 flex gap-2"><span className="text-green-600">-</span>{p}</li>
                          ))}
                        </ul>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {entry.cwes.map((c) => <span key={c} className="px-2 py-0.5 rounded text-[9px] bg-cyan-900/20 border border-cyan-800/50 text-cyan-400">{c}</span>)}
                        {entry.vuln_classes.map((v) => <span key={v} className={`px-2 py-0.5 rounded text-[9px] border ${getClassColor(v)}`}>{v}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Bug Bounty */}
          {tab === "bugbounty" && (
            <div className="space-y-2">
              {kb.bugbounty?.filter((b) => !search || b.name.toLowerCase().includes(search.toLowerCase())).map((pattern) => (
                <div key={pattern.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === pattern.id ? null : pattern.id)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <SeverityBadge severity={pattern.severity} />
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{pattern.name}</span>
                    <span className="text-[10px] text-green-400 font-mono">{pattern.bounty_range}</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] border ${getClassColor(pattern.category)}`}>{pattern.category}</span>
                  </button>
                  {expanded === pattern.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{pattern.description}</p>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Attack Steps:</div>
                        <ol className="space-y-1">
                          {pattern.steps.map((s, i) => <li key={i} className="text-[10px] text-orange-300">{i+1}. {s}</li>)}
                        </ol>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        <span className="text-[9px] text-[var(--color-text-dim)] mr-2">Found on:</span>
                        {pattern.platforms_found.map((p) => <span key={p} className="px-2 py-0.5 rounded text-[9px] bg-purple-900/20 border border-purple-800/50 text-purple-400">{p}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* WAF Bypasses */}
          {tab === "waf" && (
            <div className="space-y-2">
              {kb.waf_bypasses?.filter((w) => !search || w.name.toLowerCase().includes(search.toLowerCase())).map((bypass) => (
                <div key={bypass.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === bypass.id ? null : bypass.id)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <span className="text-xs font-mono text-pink-400 w-16 shrink-0">{bypass.id}</span>
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{bypass.name}</span>
                    <span className="px-2 py-0.5 rounded text-[9px] bg-pink-900/20 border border-pink-800/50 text-pink-400">{bypass.category}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)]">{bypass.payloads.length} payloads</span>
                  </button>
                  {expanded === bypass.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{bypass.description}</p>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Bypass Payloads:</div>
                        {bypass.payloads.map((p, i) => (
                          <pre key={i} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded px-2 py-1 mb-1 text-[10px] text-green-400 overflow-x-auto">{p}</pre>
                        ))}
                      </div>
                      <div className="flex flex-wrap gap-1">
                        <span className="text-[9px] text-[var(--color-text-dim)] mr-2">Target WAFs:</span>
                        {bypass.target_wafs.map((w) => <span key={w} className="px-2 py-0.5 rounded text-[9px] bg-blue-900/20 border border-blue-800/50 text-blue-400">{w}</span>)}
                      </div>
                      <div className="text-[10px]">
                        <span className="text-[var(--color-text-dim)]">Mitigation: </span>
                        <span className="text-green-400">{bypass.mitigation}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Cloud Security */}
          {tab === "cloud" && (
            <div className="space-y-2">
              {kb.cloud_security?.filter((c) => !search || c.name.toLowerCase().includes(search.toLowerCase())).map((pattern) => (
                <div key={pattern.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === pattern.id ? null : pattern.id)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <SeverityBadge severity={pattern.severity} />
                    <span className="px-2 py-0.5 rounded text-[9px] bg-blue-900/20 border border-blue-800/50 text-blue-400">{pattern.provider}</span>
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{pattern.name}</span>
                    <span className="px-2 py-0.5 rounded text-[9px] bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)]">{pattern.category}</span>
                  </button>
                  {expanded === pattern.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{pattern.description}</p>
                      <div className="text-[10px]"><span className="text-[var(--color-text-dim)]">Attack Vector: </span><span className="text-orange-300">{pattern.attack_vector}</span></div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Detection Indicators:</div>
                        <ul className="space-y-1">
                          {pattern.detection_indicators.map((d, i) => <li key={i} className="text-[10px] text-yellow-400">- {d}</li>)}
                        </ul>
                      </div>
                      <div className="text-[10px]"><span className="text-[var(--color-text-dim)]">Remediation: </span><span className="text-green-400">{pattern.remediation}</span></div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* API Security */}
          {tab === "api" && (
            <div className="space-y-2">
              {kb.api_security?.filter((a) => !search || a.name.toLowerCase().includes(search.toLowerCase())).map((pattern) => (
                <div key={pattern.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
                  <button onClick={() => setExpanded(expanded === pattern.id ? null : pattern.id)} className="w-full flex items-center gap-3 p-3 text-left hover:bg-[var(--color-bg)] transition-colors">
                    <SeverityBadge severity={pattern.severity} />
                    <span className="px-2 py-0.5 rounded text-[9px] bg-teal-900/20 border border-teal-800/50 text-teal-400">{pattern.owasp_api_top10}</span>
                    <span className="text-xs font-medium text-[var(--color-text)] flex-1">{pattern.name}</span>
                    <span className="px-2 py-0.5 rounded text-[9px] bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)]">{pattern.category}</span>
                  </button>
                  {expanded === pattern.id && (
                    <div className="border-t border-[var(--color-border)] p-4 space-y-3 bg-[var(--color-bg)]">
                      <p className="text-xs text-[var(--color-text-dim)]">{pattern.description}</p>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Attack Steps:</div>
                        <ol className="space-y-1">
                          {pattern.attack_steps.map((s, i) => <li key={i} className="text-[10px] text-orange-300">{i+1}. {s}</li>)}
                        </ol>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-2">Vulnerable Code:</div>
                        <pre className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded p-2 text-[10px] text-red-400 overflow-x-auto whitespace-pre-wrap">{pattern.example_vulnerable_code}</pre>
                      </div>
                      <div className="text-[10px]"><span className="text-[var(--color-text-dim)]">Remediation: </span><span className="text-green-400">{pattern.remediation}</span></div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Detectors */}
          {tab === "detectors" && (
            <div className="grid grid-cols-2 gap-3">
              {kb.detectors.map((d) => (
                <div key={d.id} className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="inline-block w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                    <span className="text-xs font-semibold text-[var(--color-text)]">{d.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] px-2 py-0.5 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text-dim)]">{d.category}</span>
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
