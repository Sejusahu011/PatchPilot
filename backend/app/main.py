from __future__ import annotations
import shutil

import asyncio
import os
import re
import tempfile
from pathlib import Path
from typing import List

import httpx
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .models import ScanResponse, Finding, FixRequest, FixResponse, VerifyResponse
from .scanners.semgrep import run_semgrep
from .scanners.osv import run_osv_scanner
from .scanners.gitleaks import run_gitleaks
from .remediation.engine import propose_fixes
from .sandbox.verify import verify_repo
from .reports.evidence_pack import build_evidence_pack
from .utils.fs import unzip_to_dir, safe_rmtree, ensure_dir

app = FastAPI(title="PatchPilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WORK_ROOT = Path(
    os.environ.get("PATCHPILOT_WORKDIR", Path(tempfile.gettempdir()) / "patchpilot")
)
ensure_dir(WORK_ROOT)


@app.get("/health")
def health():
    scanners = {
        "semgrep": shutil.which("semgrep") is not None,
        "osv-scanner": shutil.which("osv-scanner") is not None,
        "gitleaks": shutil.which("gitleaks") is not None,
    }

    status = "ok" if all(scanners.values()) else "degraded"

    return {
        "ok": True,
        "status": status,
        "scanners": scanners,
    }


def _prioritize_findings(findings: List[Finding]) -> List[Finding]:
    def score(f: Finding) -> int:
        sev = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20, "INFO": 5}.get(
            f.severity, 10
        )
        tw = {"dependency": 25, "secret": 35, "sast": 20}.get(f.category, 10)
        return sev + tw

    return sorted(findings, key=score, reverse=True)


def _scan_repo_dir(repo_dir: Path):
    semgrep = run_semgrep(repo_dir)
    osv = run_osv_scanner(repo_dir)
    gitleaks = run_gitleaks(repo_dir)

    findings: List[Finding] = []
    findings.extend(semgrep)
    findings.extend(osv)
    findings.extend(gitleaks)

    findings = _prioritize_findings(findings)

    return semgrep, osv, gitleaks, findings


def github_zip_url(repo_url: str, ref: str = "main"):
    repo_url = repo_url.strip()
    m = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url, re.IGNORECASE
    )
    if not m:
        raise ValueError(
            "Invalid GitHub URL format. Expected: https://github.com/owner/repo"
        )

    owner, repo = m.group(1), m.group(2)
    return (
        f"https://github.com/{owner}/{repo}/archive/refs/heads/{ref}.zip",
        owner,
        repo,
    )


async def check_repo_reachable(owner: str, repo: str) -> None:
    url = f"https://github.com/{owner}/{repo}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.head(url, follow_redirects=True)
            if r.status_code == 404:
                raise HTTPException(
                    status_code=422,
                    detail="Repository not found or is private. Check the URL and try again.",
                )
            if r.status_code != 200:
                raise HTTPException(
                    status_code=422,
                    detail=f"Repository not reachable (HTTP {r.status_code}).",
                )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=422,
            detail="Could not reach GitHub — check your network connection.",
        )


async def download_to_path(url: str, dest_path: Path) -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    timeout = httpx.Timeout(120.0, connect=30.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url)
        if r.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to download repo ZIP ({r.status_code}).",
            )
        dest_path.write_bytes(r.content)


def _maybe_use_single_top_folder(repo_dir: Path) -> Path:
    """
    If the extracted folder contains exactly one top-level directory (typical GitHub ZIP),
    treat that directory as the scan root.
    """
    try:
        dirs = [p for p in repo_dir.iterdir() if p.is_dir()]
        files = [p for p in repo_dir.iterdir() if p.is_file()]
    except FileNotFoundError:
        return repo_dir

    if len(dirs) == 1 and len(files) == 0:
        return dirs[0]

    return repo_dir


@app.post("/scan", response_model=ScanResponse)
async def scan(
    project: UploadFile = File(...),
    project_name: str = Form("project"),
):
    job_id = next(tempfile._get_candidate_names())
    job_dir = WORK_ROOT / job_id
    ensure_dir(job_dir)

    archive_path = job_dir / project.filename
    content = await project.read()
    archive_path.write_bytes(content)

    repo_dir = job_dir / "repo"
    ensure_dir(repo_dir)

    try:
        unzip_to_dir(archive_path, repo_dir)
    except Exception as e:
        safe_rmtree(job_dir)
        raise HTTPException(status_code=400, detail=f"Invalid zip upload: {e}")

    scan_root = _maybe_use_single_top_folder(repo_dir)

    semgrep, osv, gitleaks, findings = _scan_repo_dir(scan_root)

    return ScanResponse(
        job_id=job_id,
        project_name=project_name,
        repo_path=str(scan_root),
        findings=findings,
        scanners={
            "semgrep": {"ok": True, "count": len(semgrep)},
            "osv": {"ok": True, "count": len(osv)},
            "gitleaks": {"ok": True, "count": len(gitleaks)},
        },
    )


@app.post("/scan-url", response_model=ScanResponse)
async def scan_url(
    repo_url: str = Form(...),
    ref: str = Form("main"),
    project_name: str = Form("project"),
):
    job_id = next(tempfile._get_candidate_names())
    job_dir = WORK_ROOT / job_id
    ensure_dir(job_dir)

    archive_path = job_dir / "repo.zip"
    repo_dir = job_dir / "repo"
    ensure_dir(repo_dir)

    try:
        zip_url, owner, repo = github_zip_url(repo_url, ref=ref)
    except ValueError as e:
        safe_rmtree(job_dir)
        raise HTTPException(status_code=422, detail=str(e))

    try:
        await check_repo_reachable(owner, repo)
    except HTTPException:
        safe_rmtree(job_dir)
        raise

    try:
        await asyncio.wait_for(download_to_path(zip_url, archive_path), timeout=30.0)
        unzip_to_dir(archive_path, repo_dir)
    except asyncio.TimeoutError:
        safe_rmtree(job_dir)
        raise HTTPException(status_code=504, detail="Repository clone timed out.")
    except HTTPException:
        safe_rmtree(job_dir)
        raise
    except Exception as e:
        safe_rmtree(job_dir)
        raise HTTPException(status_code=400, detail=f"Import from URL failed: {e}")

    scan_root = _maybe_use_single_top_folder(repo_dir)

    semgrep, osv, gitleaks, findings = _scan_repo_dir(scan_root)

    return ScanResponse(
        job_id=job_id,
        project_name=project_name,
        repo_path=str(scan_root),
        findings=findings,
        scanners={
            "semgrep": {"ok": True, "count": len(semgrep)},
            "osv": {"ok": True, "count": len(osv)},
            "gitleaks": {"ok": True, "count": len(gitleaks)},
        },
    )


@app.post("/fix", response_model=FixResponse)
def fix(req: FixRequest):
    job_dir = WORK_ROOT / req.job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    repo_dir = _maybe_use_single_top_folder(repo_dir)
    fixes = propose_fixes(repo_dir, req.finding_ids)

    return FixResponse(job_id=req.job_id, fixes=fixes)


@app.post("/verify", response_model=VerifyResponse)
def verify(job_id: str = Form(...)):
    job_dir = WORK_ROOT / job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    repo_dir = _maybe_use_single_top_folder(repo_dir)
    result = verify_repo(repo_dir)
    return result


@app.post("/evidence-pack")
def evidence_pack(job_id: str = Form(...), project_name: str = Form("project")):
    job_dir = WORK_ROOT / job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    repo_dir = _maybe_use_single_top_folder(repo_dir)

    out_dir = job_dir / "out"
    ensure_dir(out_dir)

    pack_path = build_evidence_pack(
        repo_dir=repo_dir, out_dir=out_dir, project_name=project_name, job_id=job_id
    )
    return FileResponse(
        path=str(pack_path), filename=pack_path.name, media_type="application/zip"
    )


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    job_dir = WORK_ROOT / job_id
    if job_dir.exists():
        safe_rmtree(job_dir)
    return {"deleted": True}
