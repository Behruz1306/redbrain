"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface BrainStats {
  total_scans: number;
  embedding_corpus_size: number;
  gbrain_pages: number;
  total_patterns: number;
}

type ScanMode = "full" | "code_only";

export default function Home() {
  const [repoUrl, setRepoUrl] = useState("");
  const [deployedUrl, setDeployedUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<BrainStats | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const router = useRouter();

  useEffect(() => {
    fetch("/api/brain/knowledge")
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: repoUrl,
          deployed_url: scanMode === "full" ? deployedUrl : "",
        }),
      });
      const data = await res.json();
      router.push(`/scan/${data.scan_id}`);
    } catch (err) {
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl space-y-10">
        {/* Logo */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight">
            <span className="text-[var(--color-critical)]">Red</span>
            <span className="text-[var(--color-text)]">Brain</span>
            <span className="cursor-blink ml-1"></span>
          </h1>
          <p className="text-[var(--color-text-dim)] text-sm max-w-md mx-auto">
            Autonomous AI security engineer. 16 detectors, 71 CVEs, 44 techniques,
            15 bug bounty patterns, OWASP Top 10. Self-compounding knowledge graph.
          </p>
          <div className="flex items-center justify-center gap-2 text-[9px] text-[var(--color-text-dim)] flex-wrap">
            <span className="px-2 py-0.5 rounded border border-purple-800/50 text-purple-400">GStack</span>
            <span className="px-2 py-0.5 rounded border border-blue-800/50 text-blue-400">GBrain</span>
            <span className="px-2 py-0.5 rounded border border-green-800/50 text-green-400">ZeroEntropy</span>
            <span className="px-2 py-0.5 rounded border border-yellow-800/50 text-yellow-400">Gemini</span>
            <span className="px-2 py-0.5 rounded border border-orange-800/50 text-orange-400">The Hog</span>
            <span className="px-2 py-0.5 rounded border border-cyan-800/50 text-cyan-400">Jo/Camofox</span>
          </div>
        </div>

        {/* Scan Mode Selector */}
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setScanMode("full")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
              scanMode === "full"
                ? "bg-[var(--color-accent)] text-[var(--color-bg)]"
                : "bg-[var(--color-surface)] text-[var(--color-text-dim)] border border-[var(--color-border)] hover:border-[var(--color-accent)]"
            }`}
          >
            Full Scan (SAST + DAST)
          </button>
          <button
            onClick={() => setScanMode("code_only")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
              scanMode === "code_only"
                ? "bg-purple-600 text-white"
                : "bg-[var(--color-surface)] text-[var(--color-text-dim)] border border-[var(--color-border)] hover:border-purple-500"
            }`}
          >
            Code-Only (GitHub)
          </button>
        </div>

        {/* Scan Form */}
        <form onSubmit={handleScan} className="space-y-4">
          <div className="space-y-3">
            <div className="relative">
              <label className="block text-xs text-[var(--color-text-dim)] mb-1.5 uppercase tracking-wider">
                GitHub Repository
              </label>
              <input
                type="url"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/juice-shop/juice-shop"
                required
                className="w-full bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-4 py-3 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] focus:ring-1 focus:ring-[var(--color-accent)] transition-colors"
              />
            </div>
            {scanMode === "full" && (
              <div className="relative">
                <label className="block text-xs text-[var(--color-text-dim)] mb-1.5 uppercase tracking-wider">
                  Deployed URL
                </label>
                <input
                  type="url"
                  value={deployedUrl}
                  onChange={(e) => setDeployedUrl(e.target.value)}
                  placeholder="https://benjamin11133-juice-shop.hf.space"
                  required
                  className="w-full bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-4 py-3 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] focus:ring-1 focus:ring-[var(--color-accent)] transition-colors"
                />
              </div>
            )}
            {scanMode === "code_only" && (
              <div className="bg-purple-900/20 border border-purple-800/30 rounded-lg p-3">
                <p className="text-xs text-purple-300">
                  Code-only mode: RedBrain will clone the repository and run deep static analysis
                  with 16 detectors + AI-powered complex vulnerability detection. No deployment needed.
                </p>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className={`w-full font-semibold py-3 rounded-lg text-sm uppercase tracking-wider transition-all disabled:opacity-50 disabled:cursor-not-allowed glow-pulse ${
              scanMode === "full"
                ? "bg-[var(--color-accent)] text-[var(--color-bg)] hover:brightness-110"
                : "bg-purple-600 text-white hover:bg-purple-500"
            }`}
          >
            {loading
              ? "[ INITIALIZING AI AGENTS... ]"
              : scanMode === "full"
              ? "[ START FULL AI SCAN ]"
              : "[ ANALYZE CODE ]"}
          </button>
        </form>

        {/* Quick Targets */}
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-3">
          <div className="text-xs font-semibold text-[var(--color-text-dim)] uppercase tracking-wider">
            Quick Targets (click to fill)
          </div>
          <div className="grid grid-cols-1 gap-2">
            <button
              type="button"
              onClick={() => {
                setRepoUrl("https://github.com/juice-shop/juice-shop");
                setDeployedUrl("https://benjamin11133-juice-shop.hf.space");
                setScanMode("full");
              }}
              className="text-left px-3 py-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] hover:border-[var(--color-accent)] transition-colors"
            >
              <div className="text-xs font-medium text-[var(--color-text)]">OWASP Juice Shop</div>
              <div className="text-[10px] text-[var(--color-text-dim)]">Full scan — intentionally vulnerable Node.js app (OWASP Top 10)</div>
            </button>
            <button
              type="button"
              onClick={() => {
                setRepoUrl("https://github.com/OWASP/NodeGoat");
                setScanMode("code_only");
              }}
              className="text-left px-3 py-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] hover:border-purple-500 transition-colors"
            >
              <div className="text-xs font-medium text-purple-300">OWASP NodeGoat</div>
              <div className="text-[10px] text-[var(--color-text-dim)]">Code-only — vulnerable Node.js app for learning OWASP risks</div>
            </button>
            <button
              type="button"
              onClick={() => {
                setRepoUrl("https://github.com/payloadbox/xss-payload-list");
                setScanMode("code_only");
              }}
              className="text-left px-3 py-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] hover:border-purple-500 transition-colors"
            >
              <div className="text-xs font-medium text-purple-300">XSS Payload Collection</div>
              <div className="text-[10px] text-[var(--color-text-dim)]">Code-only — Analyze XSS payloads and patterns</div>
            </button>
          </div>
        </div>

        {/* Feature cards */}
        <div className="grid grid-cols-3 gap-3">
          {[
            {
              title: "Semantic SAST",
              desc: "16 detectors + AI deep analysis. CVE matching via ZeroEntropy + Gemini validation",
              badge: "zembed-1",
            },
            {
              title: "Stealth DAST",
              desc: "WAF-bypassing recon via Jo Camofox + payload ranking via ZeroEntropy reranking",
              badge: "Camofox",
            },
            {
              title: "Threat Intel",
              desc: "Real-time social listening for exploit discussions via The Hog intelligence",
              badge: "The Hog",
            },
          ].map((f) => (
            <div
              key={f.title}
              className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-2"
            >
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-semibold text-[var(--color-accent)] uppercase">
                  {f.title}
                </h3>
                <span className="text-[8px] px-1.5 py-0.5 rounded bg-[var(--color-bg)] text-[var(--color-text-dim)] border border-[var(--color-border)]">
                  {f.badge}
                </span>
              </div>
              <p className="text-xs text-[var(--color-text-dim)]">{f.desc}</p>
            </div>
          ))}
        </div>

        {/* Live Stats */}
        <div className="flex justify-center gap-6 text-xs text-[var(--color-text-dim)] flex-wrap">
          <span>
            CVEs: <span className="text-[var(--color-text)]">71</span>
          </span>
          <span>
            Techniques: <span className="text-[var(--color-text)]">44</span>
          </span>
          <span>
            Bug Bounty: <span className="text-[var(--color-text)]">15</span>
          </span>
          <span>
            OWASP: <span className="text-[var(--color-text)]">10</span>
          </span>
          <span>
            Detectors: <span className="text-[var(--color-text)]">16</span>
          </span>
          <span>
            Graph: <span className="text-[var(--color-text)]">{stats?.gbrain_pages ?? "..."} nodes</span>
          </span>
        </div>

        {/* Navigation */}
        <div className="flex justify-center gap-6">
          <a
            href="/brain"
            className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)] transition-colors underline underline-offset-4"
          >
            Brain Graph →
          </a>
          <a
            href="/kb"
            className="text-xs text-[var(--color-text-dim)] hover:text-purple-400 transition-colors underline underline-offset-4"
          >
            Knowledge Base →
          </a>
          <a
            href="/developers"
            className="text-xs text-[var(--color-text-dim)] hover:text-green-400 transition-colors underline underline-offset-4"
          >
            API / MCP →
          </a>
        </div>
      </div>
    </main>
  );
}
