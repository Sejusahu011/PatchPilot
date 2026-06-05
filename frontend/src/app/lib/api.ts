const API_BASE =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

export type HealthResponse = {
  ok: boolean;
  status: "healthy" | "degraded";
  scanners: Record<string, boolean>;
};

export async function getHealth() {
  const res = await fetch(`${API_BASE}/health`);

  if (!res.ok) {
    throw new Error(await res.text());
  }

  return (await res.json()) as HealthResponse;
}


export type ScanResponse = {
  job_id: string;
  project_name: string;
  repo_path: string;
  scanners: Record<string, { ok: boolean; count: number }>;
  findings: BackendFinding[];
};

export type BackendFinding = {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  title: string;
  file: string;
  line: number;
  tool: "semgrep" | "osv" | "gitleaks" | string;
  confidence?: number;
  description?: string;
  code?: string;
  suggested_fix?: string;
  references?: string[];
};

export async function scanZip(file: File, projectName = "project") {
  const form = new FormData();
  form.append("project", file);
  form.append("project_name", projectName);

  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    throw new Error(await res.text());
  }

  return (await res.json()) as ScanResponse;
}

export async function scanRepoUrl(
  repoUrl: string,
  ref = "main",
  projectName = "project",
) {
  const form = new FormData();
  form.append("repo_url", repoUrl);
  form.append("ref", ref);
  form.append("project_name", projectName);

  const res = await fetch(`${API_BASE}/scan-url`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => null);
    throw new Error(err?.detail ?? "Import from URL failed");
  }

  return (await res.json()) as ScanResponse;
}

export async function fix(jobId: string, findingIds: string[]) {
  const res = await fetch(`${API_BASE}/fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ job_id: jobId, finding_ids: findingIds }),
  });

  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function verify(jobId: string) {
  const form = new FormData();
  form.append("job_id", jobId);

  const res = await fetch(`${API_BASE}/verify`, { method: "POST", body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

/**
 * POST /evidence-pack -> returns a ZIP (FileResponse)
 * This fetches it as a Blob and tries to infer a filename from Content-Disposition.
 */
export async function downloadEvidencePack(
  jobId: string,
  projectName = "project",
) {
  const form = new FormData();
  form.append("job_id", jobId);
  form.append("project_name", projectName);

  const res = await fetch(`${API_BASE}/evidence-pack`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    throw new Error(await res.text());
  }

  const blob = await res.blob();

  const cd = res.headers.get("content-disposition") || "";
  const match = cd.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] || `evidence-pack-${jobId}.zip`;

  return { blob, filename };
}

export type TrendData = {
  date: string;
  findings: number;
};

export async function getTrends(limit = 6) {
  const res = await fetch(`${API_BASE}/trends?limit=${limit}`);
  if (!res.ok) throw new Error(await res.text());
  return (await res.json()) as TrendData[];
}
