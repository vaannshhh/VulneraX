"""
VulneraX — FastAPI REST API
=============================
Provides HTTP access to all scanning capabilities.

Endpoints
---------
POST /scan               Start a new scan (returns scan_id)
GET  /status/{scan_id}   Query scan progress / status
GET  /report/{scan_id}   Retrieve the full JSON report
GET  /scans              List all completed scans
GET  /health             Health check
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.orchestrator import Orchestrator
from reports.report_generator import ReportGenerator
from utils.logger import get_logger, setup_logging
from utils.schema import ScanResult

log = get_logger("vulnerax.api")

# ── In-memory state store ─────────────────────────────────────────────
# Production deployments should replace this with Redis or a DB.
_SCANS: Dict[str, Dict[str, Any]] = {}
_RESULTS: Dict[str, ScanResult] = {}
_LOCK = threading.Lock()

app = FastAPI(
    title="VulneraX API",
    description="Intelligent Automated Vulnerability Assessment Framework",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_logging()


# ── Request / Response models ─────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., example="https://example.com", description="URL, IP, or domain to scan")
    scan_type: str = Field("full", example="full", description="'quick' | 'full' | 'custom'")
    custom_scanners: Optional[List[str]] = Field(
        None, example=["nmap", "nuclei"], description="Scanner list (used when scan_type='custom')"
    )


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    message: str


class StatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str          # 'queued' | 'running' | 'complete' | 'error'
    progress: int        # 0–100
    current_step: str
    total_findings: Optional[int] = None
    errors: List[str] = []


# ── Background worker ─────────────────────────────────────────────────

def _run_scan(scan_id: str, target: str, scan_type: str, custom: list) -> None:
    def _progress(message: str, percent: int) -> None:
        with _LOCK:
            _SCANS[scan_id]["progress"] = percent
            _SCANS[scan_id]["current_step"] = message

    with _LOCK:
        _SCANS[scan_id]["status"] = "running"

    try:
        orch = Orchestrator(progress_callback=_progress)
        result = orch.run(
            target=target,
            scan_type=scan_type,
            custom_scanners=custom or None,
        )
        paths = ReportGenerator().generate(result)

        with _LOCK:
            _RESULTS[scan_id] = result
            _SCANS[scan_id].update({
                "status": "complete",
                "progress": 100,
                "total_findings": result.total,
                "report_paths": paths,
            })
        log.info("API scan %s complete — %d findings.", scan_id, result.total)

    except Exception as exc:  # noqa: BLE001
        log.error("API scan %s failed: %s", scan_id, exc, exc_info=True)
        with _LOCK:
            _SCANS[scan_id].update({"status": "error", "error": str(exc)})


# ── Routes ────────────────────────────────────────────────────────────

@app.get("/health", tags=["meta"])
def health_check() -> dict:
    """Returns API health status."""
    return {"status": "ok", "service": "VulneraX API", "version": "1.0.0"}


@app.post("/scan", response_model=ScanResponse, status_code=202, tags=["scanning"])
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    """
    Initiate an asynchronous vulnerability scan.

    Returns a ``scan_id`` that can be used to poll ``/status/{scan_id}``.
    """
    scan_id = str(uuid.uuid4())
    with _LOCK:
        _SCANS[scan_id] = {
            "scan_id":     scan_id,
            "target":      request.target,
            "scan_type":   request.scan_type,
            "status":      "queued",
            "progress":    0,
            "current_step": "Queued",
            "total_findings": None,
            "errors":      [],
        }

    background_tasks.add_task(
        _run_scan, scan_id, request.target, request.scan_type,
        request.custom_scanners or [],
    )
    log.info("Scan queued: %s → %s (%s)", scan_id[:8], request.target, request.scan_type)
    return ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="queued",
        message=f"Scan queued. Poll /status/{scan_id} for updates.",
    )


@app.get("/status/{scan_id}", response_model=StatusResponse, tags=["scanning"])
def get_status(scan_id: str) -> StatusResponse:
    """Retrieve the current status and progress of a scan."""
    with _LOCK:
        scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return StatusResponse(
        scan_id=scan_id,
        target=scan["target"],
        status=scan["status"],
        progress=scan.get("progress", 0),
        current_step=scan.get("current_step", ""),
        total_findings=scan.get("total_findings"),
        errors=scan.get("errors", []),
    )


@app.get("/report/{scan_id}", tags=["reporting"])
def get_report(scan_id: str) -> dict:
    """
    Retrieve the complete JSON report for a finished scan.

    Returns 404 if the scan is not yet complete or doesn't exist.
    """
    with _LOCK:
        scan = _SCANS.get(scan_id)
        result = _RESULTS.get(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    if scan["status"] != "complete":
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not complete yet (status: {scan['status']})."
        )
    if not result:
        raise HTTPException(status_code=500, detail="Scan result data missing.")

    return result.to_dict()


@app.get("/scans", tags=["reporting"])
def list_scans() -> list:
    """Return a summary list of all scans (queued, running, and complete)."""
    with _LOCK:
        return [
            {
                "scan_id":       s["scan_id"],
                "target":        s["target"],
                "status":        s["status"],
                "total_findings": s.get("total_findings"),
            }
            for s in _SCANS.values()
        ]
