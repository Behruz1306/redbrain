"use client";

import { useState } from "react";

interface ScanFormProps {
  onSubmit: (repoUrl: string, deployedUrl: string) => void;
  loading: boolean;
}

export function ScanForm({ onSubmit, loading }: ScanFormProps) {
  const [repoUrl, setRepoUrl] = useState("");
  const [deployedUrl, setDeployedUrl] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSubmit(repoUrl, deployedUrl);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-3">
        <div>
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
        <div>
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
  );
}
