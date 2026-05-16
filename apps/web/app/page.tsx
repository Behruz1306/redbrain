"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface BrainStats {
  total_scans: number;
  embedding_corpus_size: number;
  gbrain_pages: number;
  total_patterns: number;
}

export default function Home() {
  const [repoUrl, setRepoUrl] = useState("");
  const [deployedUrl, setDeployedUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<BrainStats | null>(null);
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
          deployed_url: deployedUrl,
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
      <div className="w-full max-w-2xl space-y-12">
        {/* Logo */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight">
            <span className="text-[var(--color-critical)]">Red</span>
            <span className="text-[var(--color-text)]">Brain</span>
            <span className="cursor-blink ml-1"></span>
          </h1>
          <p className="text-[var(--color-text-dim)] text-sm max-w-md mx-auto">
            Autonomous AI security engineer powered by ZeroEntropy semantic intelligence.
            SAST + DAST + knowledge graph in one brain.
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
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[var(--color-accent)] text-[var(--color-bg)] font-semibold py-3 rounded-lg text-sm uppercase tracking-wider hover:brightness-110 transition-all disabled:opacity-50 disabled:cursor-not-allowed glow-pulse"
          >
            {loading ? "[ INITIALIZING AI AGENTS... ]" : "[ START AI SCAN ]"}
          </button>
        </form>

        {/* Feature cards */}
        <div className="grid grid-cols-3 gap-3">
          {[
            {
              title: "Semantic SAST",
              desc: "AI-powered static analysis with CVE matching via ZeroEntropy + Gemini validation",
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
        <div className="flex justify-center gap-8 text-xs text-[var(--color-text-dim)]">
          <span>
            Scans completed:{" "}
            <span className="text-[var(--color-text)]">{stats?.total_scans ?? "..."}</span>
          </span>
          <span>
            Knowledge pages:{" "}
            <span className="text-[var(--color-text)]">{stats?.gbrain_pages ?? "..."}</span>
          </span>
          <span>
            Embeddings:{" "}
            <span className="text-[var(--color-text)]">{stats?.embedding_corpus_size ?? "..."}</span>
          </span>
        </div>

        {/* Navigation */}
        <div className="flex justify-center">
          <a
            href="/brain"
            className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)] transition-colors underline underline-offset-4"
          >
            Explore Brain Graph →
          </a>
        </div>
      </div>
    </main>
  );
}
