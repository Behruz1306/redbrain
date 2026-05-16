export interface ScanCreateResponse {
  scan_id: string;
  ws_url: string;
}

export interface VulnerabilityData {
  id: string;
  vuln_class: string;
  severity: string;
  status: string;
  confidence: number;
  title: string;
  description: string;
  function_id?: string;
  endpoint_id?: string;
}

export interface ReportStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  bounty_value: number;
}

export interface ReportData {
  vulnerabilities: VulnerabilityData[];
  report_markdown: string;
  stats: ReportStats;
}

export interface GraphData {
  nodes: Array<{ id: string; label: string; type: string }>;
  edges: Array<{ source: string; target: string; label?: string }>;
}

const API_BASE = "/api";

export async function createScan(
  repoUrl: string,
  deployedUrl: string
): Promise<ScanCreateResponse> {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl, deployed_url: deployedUrl }),
  });
  if (!res.ok) throw new Error(`Scan creation failed: ${res.status}`);
  return res.json();
}

export async function getReport(scanId: string): Promise<ReportData> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/report`);
  if (!res.ok) throw new Error(`Report fetch failed: ${res.status}`);
  return res.json();
}

export async function getBrainGraph(scanId?: string): Promise<GraphData> {
  const params = scanId ? `?scan_id=${scanId}` : "";
  const res = await fetch(`${API_BASE}/brain/graph${params}`);
  if (!res.ok) throw new Error(`Graph fetch failed: ${res.status}`);
  return res.json();
}
