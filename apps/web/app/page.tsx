"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const [repoUrl, setRepoUrl] = useState("");
  const [deployedUrl, setDeployedUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

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
            Autonomous AI security engineer. SAST + DAST + threat intel in one
            brain.
          </p>
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
                placeholder="http://localhost:3000"
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
            {loading ? "[ INITIALIZING... ]" : "[ START SCAN ]"}
          </button>
        </form>

        {/* Feature cards */}
        <div className="grid grid-cols-3 gap-3">
          {[
            {
              title: "Reads your code",
              desc: "Static analysis with 6 vulnerability patterns",
            },
            {
              title: "Attacks your app",
              desc: "Dynamic exploitation with targeted payloads",
            },
            {
              title: "Connects the dots",
              desc: "Knowledge graph correlates code to exploits",
            },
          ].map((f) => (
            <div
              key={f.title}
              className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 space-y-2"
            >
              <h3 className="text-xs font-semibold text-[var(--color-accent)] uppercase">
                {f.title}
              </h3>
              <p className="text-xs text-[var(--color-text-dim)]">{f.desc}</p>
            </div>
          ))}
        </div>

        {/* Stats */}
        <div className="flex justify-center gap-8 text-xs text-[var(--color-text-dim)]">
          <span>
            Total scans: <span className="text-[var(--color-text)]">1,247</span>
          </span>
          <span>
            CVEs in brain:{" "}
            <span className="text-[var(--color-text)]">12,384</span>
          </span>
        </div>
      </div>
    </main>
  );
}
