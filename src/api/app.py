"""
GraphQL Guardian Web API
FastAPI backend for web dashboard.
"""

from datetime import datetime
import asyncio
import os
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import AnyHttpUrl, BaseModel
from typing import Optional, Dict, List, Any
import uuid
from pathlib import Path
import sys
import json
import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.api.database import Database
from src.api.benchmark_task import BenchmarkTask
from src.api.exports import (
    build_finding_dossier,
    build_repeater_collection,
    render_finding_dossier_text,
    render_intruder_payloads,
    render_relationship_map_text,
    render_manual_finding_provenance_text,
    render_operation_pack_text,
    render_operation_pack_http,
    render_points_of_interest_text,
    to_pretty_json,
)
from src.api.scanner_task import ScannerTask
from src.reporters.finding_enricher import enrich_finding_dicts
from src.reporters.relationship_map import build_relationship_map
from src.reporters.schema_map import build_schema_map
from src.risk.rating import rate_finding
from src.scanner.dvga_benchmark import render_benchmark_markdown

app = FastAPI(
    title="GraphQL Guardian API",
    description="REST API for GraphQL security scanning",
    version="1.0.0"
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://127.0.0.1:8080",
    ],  # React/Vite dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db = Database()
DEFAULT_TARGET_ENDPOINT = os.getenv("GUARDQL_DEFAULT_TARGET_ENDPOINT", "http://localhost:5013/graphql")

# In-memory task tracker (for background scans)
active_tasks: Dict[str, ScannerTask] = {}
active_benchmark_tasks: Dict[str, BenchmarkTask] = {}


# Request/Response Models
class ScanRequest(BaseModel):
    """Request body for POST /scan"""
    endpoint: AnyHttpUrl
    enable_ml: bool = False
    enable_llm: bool = False
    risk_level: int = 1
    technique: str = "IDAC"
    profile: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """Response for GET /scan/{id}/status"""
    id: str
    status: str  # pending, running, completed, failed
    endpoint: str
    progress: float  # 0.0 to 1.0
    start_time: str
    end_time: Optional[str] = None
    error: Optional[str] = None
    phase: Optional[str] = None


class ScanSummary(BaseModel):
    """Summary of scan results"""
    total: int
    high: int
    medium: int
    low: int
    info: int


class BenchmarkRequest(BaseModel):
    """Request body for POST /benchmarks/dvga"""
    endpoint: AnyHttpUrl = DEFAULT_TARGET_ENDPOINT
    label: Optional[str] = None
    group: Optional[str] = None
    profile: str = "default"
    enable_ml: bool = False
    enable_llm: bool = False


class BenchmarkStatusResponse(BaseModel):
    id: str
    status: str
    endpoint: str
    label: Optional[str] = None
    group: Optional[str] = None
    progress: float
    start_time: str
    end_time: Optional[str] = None
    error: Optional[str] = None
    phase: Optional[str] = None


class ManualNoteRequest(BaseModel):
    operation_name: str
    status: str = "queued"
    observations: str = ""
    payload_tweaks: str = ""
    request_override: Optional[Dict[str, Any]] = None


class ManualReplayRequest(BaseModel):
    operation_name: str
    request_override: Dict[str, Any]
    status: str = "queued"
    observations: str = ""
    payload_tweaks: str = ""


class ManualPromotionRequest(BaseModel):
    operation_name: str
    severity: str = "MEDIUM"
    category: str = "AUTH"
    title: Optional[str] = None
    description: Optional[str] = None
    reproduction: Optional[str] = None


# API Endpoints
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "ok",
        "service": "GraphQL Guardian API",
        "version": "1.0.0"
    }


@app.post("/scan", response_model=Dict[str, str])
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new security scan task.
    Returns task ID for status tracking.
    """
    task_id = str(uuid.uuid4())
    
    # Store scan metadata first so the dashboard can track this run by scan_id.
    db.create_scan(
        scan_id=task_id,
        endpoint=str(request.endpoint),
        config={
            "enable_ml": request.enable_ml,
            "enable_llm": request.enable_llm,
            "risk_level": request.risk_level,
            "technique": request.technique,
            "profile": request.profile,
        }
    )
    
    # Keep the scanner task in memory while the background scan is running.
    task = ScannerTask(
        task_id=task_id,
        endpoint=str(request.endpoint),
        enable_ml=request.enable_ml,
        enable_llm=request.enable_llm,
        risk_level=request.risk_level,
        technique=request.technique,
        profile=request.profile,
    )
    
    active_tasks[task_id] = task
    
    # Run the scan in the background so the API can return the scan_id immediately.
    background_tasks.add_task(run_scan, task_id, task)
    
    return {
        "scan_id": task_id,
        "status": "pending",
        "message": "Scan task created successfully"
    }


async def run_scan(task_id: str, task: ScannerTask):
    """Background task to execute the scan"""
    try:
        # Mark the scan as running before the blocking scanner starts.
        db.update_scan_status(task_id, "running")
        
        # Execute the scanner in a worker thread because the scan is CPU/network bound.
        results = await asyncio.to_thread(task.run)
        
        # Store the final scanner output for report and schema map retrieval.
        db.save_scan_results(task_id, results)
        
        # Mark the scan as completed only after results are saved.
        db.update_scan_status(task_id, "completed")
        
    except Exception as e:
        # Update status to failed with error
        db.update_scan_status(task_id, "failed", error=str(e))
        task.status = "failed"
        task.error = str(e)


@app.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get the current status of a scan task.
    """
    # Get from database
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get live progress from active task if running
    progress = 0.0
    phase = None
    if scan_id in active_tasks:
        progress = active_tasks[scan_id].progress
        phase = active_tasks[scan_id].current_phase
    elif scan["status"] == "completed":
        progress = 1.0
        phase = "Completed"
    
    return ScanStatusResponse(
        id=scan["id"],
        status=scan["status"],
        endpoint=scan["endpoint"],
        progress=progress,
        start_time=scan["start_time"],
        end_time=scan.get("end_time"),
        error=scan.get("error"),
        phase=phase
    )


@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """
    Get the full JSON report for a completed scan.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed yet (status: {scan['status']})"
        )
    
    # Get results from database
    results = db.get_scan_results(scan_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return _enrich_scan_report(results)


@app.get("/scan/{scan_id}/manual-notes")
async def get_manual_notes(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "notes": db.list_manual_notes(scan_id)
    }


@app.put("/scan/{scan_id}/manual-note")
async def save_manual_note(scan_id: str, request: ManualNoteRequest):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    note = db.save_manual_note(
        scan_id=scan_id,
        operation_name=request.operation_name,
        status=request.status,
        observations=request.observations,
        payload_tweaks=request.payload_tweaks,
        request_override=request.request_override,
    )
    return note


@app.post("/scan/{scan_id}/manual-replay")
async def replay_manual_request(scan_id: str, request: ManualReplayRequest):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not request.request_override.get("query"):
        raise HTTPException(status_code=400, detail="Replay request must include a GraphQL query")

    recorded_at = datetime.now().isoformat()
    try:
        response = requests.post(
            scan["endpoint"],
            json=request.request_override,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=20,
        )
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:12000]

        replay_result = {
            "ok": response.ok,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "recorded_at": recorded_at,
        }
    except requests.RequestException as exc:
        replay_result = {
            "ok": False,
            "status_code": None,
            "headers": {},
            "body": None,
            "elapsed_ms": None,
            "recorded_at": recorded_at,
            "error": str(exc),
        }

    history_entry = db.save_manual_replay(
        scan_id=scan_id,
        operation_name=request.operation_name,
        request_override=request.request_override,
        replay_result=replay_result,
    )
    note = db.save_manual_note(
        scan_id=scan_id,
        operation_name=request.operation_name,
        status=request.status,
        observations=request.observations,
        payload_tweaks=request.payload_tweaks,
        request_override=request.request_override,
        last_replay=replay_result,
    )
    note["latest_replay_entry"] = history_entry
    return note


@app.get("/scan/{scan_id}/manual-replays")
async def get_manual_replays(
    scan_id: str,
    operation_name: str,
    limit: int = Query(default=6, ge=1, le=20),
):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "replays": db.list_manual_replays(scan_id, operation_name, limit=limit)
    }


@app.post("/scan/{scan_id}/manual-note/promote")
async def promote_manual_note(scan_id: str, request: ManualPromotionRequest):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    note = db.get_manual_note(scan_id, request.operation_name)
    if not note:
        raise HTTPException(status_code=404, detail="Manual note not found")

    finding = {
        "category": request.category.upper(),
        "title": request.title or f"Manual validation: {request.operation_name}",
        "description": request.description or note.get("observations") or "Manual validation recorded in Guardian.",
        "reproduction": request.reproduction
        or build_manual_reproduction(scan["endpoint"], note.get("request_override")),
        "evidence": {
            "source": "manual",
            "observations": note.get("observations"),
            "payload_tweaks": note.get("payload_tweaks"),
            "last_replay": note.get("last_replay"),
        },
        "operation_name": request.operation_name,
    }
    finding["risk"] = rate_finding(category=finding["category"], severity=request.severity.upper())
    finding["severity"] = finding["risk"]["severity"]

    try:
        result = db.promote_manual_note_to_finding(scan_id, request.operation_name, finding)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return result


@app.get("/scan/{scan_id}/export/{artifact_name}")
async def export_scan_artifact(
    scan_id: str,
    artifact_name: str,
    format: str = Query(default="json"),
    finding_id: Optional[str] = Query(default=None),
):
    """Export operation pack or points of interest for manual workflows."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")

    result = db.get_scan_results(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan results not found")
    result = _enrich_scan_report(result)

    if artifact_name == "manual-provenance":
        items = db.list_manual_finding_provenance(scan_id, finding_id=finding_id)
        if finding_id and not items:
            raise HTTPException(status_code=404, detail="Requested manual finding was not found")

        payload = {
            "scan_id": scan_id,
            "endpoint": result.get("metadata", {}).get("endpoint"),
            "exported_at": datetime.now().isoformat(),
            "finding_id": finding_id,
            "items": items,
        }

        if format == "txt":
            content = render_manual_finding_provenance_text(payload)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "json":
            content = to_pretty_json(payload)
            media_type = "application/json"
            extension = "json"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")

        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="manual-provenance-{scan_id}.{extension}"'
            },
        )

    artifact_map = {
        "operation-pack": ("operation_pack", render_operation_pack_text, "operation-pack"),
        "points-of-interest": ("points_of_interest", render_points_of_interest_text, "points-of-interest"),
        "relationship-map": ("relationship_map", render_relationship_map_text, "relationship-map"),
    }
    if artifact_name == "finding-dossier":
        payload = build_finding_dossier(result, scan_id=scan_id, finding_id=finding_id)
        if format == "txt":
            content = render_finding_dossier_text(payload)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "json":
            content = to_pretty_json(payload)
            media_type = "application/json"
            extension = "json"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")

        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="finding-dossier-{scan_id}.{extension}"'
            },
        )

    if artifact_name not in artifact_map:
        raise HTTPException(status_code=404, detail="Unknown export artifact")

    key, text_renderer, filename_prefix = artifact_map[artifact_name]
    payload = result.get(key)
    if payload is None:
        raise HTTPException(status_code=404, detail="Requested artifact not found")

    if artifact_name == "operation-pack":
        if format == "txt":
            content = text_renderer(result)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "http":
            content = render_operation_pack_http(result)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "intruder":
            content = render_intruder_payloads(result)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "repeater":
            content = to_pretty_json(build_repeater_collection(result))
            media_type = "application/json"
            extension = "json"
        elif format == "json":
            content = to_pretty_json(payload)
            media_type = "application/json"
            extension = "json"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
    else:
        if format == "txt":
            content = text_renderer(result)
            media_type = "text/plain; charset=utf-8"
            extension = "txt"
        elif format == "json":
            content = to_pretty_json(payload)
            media_type = "application/json"
            extension = "json"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename_prefix}-{scan_id}.{extension}"'
        },
    )


@app.get("/scan/{scan_id}/graph")
async def get_scan_graph(scan_id: str):
    """
    Get the schema relationship graph for visualization.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed yet (status: {scan['status']})"
        )
    
    report = db.get_scan_results(scan_id)
    if report:
        return build_schema_map(report)

    graph_data = db.get_scan_graph(scan_id)
    return graph_data or {"nodes": [], "edges": [], "summary": {}}


@app.post("/benchmarks/dvga", response_model=Dict[str, str])
async def create_benchmark(request: BenchmarkRequest, background_tasks: BackgroundTasks):
    """Create a new DVGA benchmark task."""
    benchmark_id = str(uuid.uuid4())
    db.create_benchmark(
        benchmark_id=benchmark_id,
        endpoint=str(request.endpoint),
        config={
            "label": request.label,
            "group": request.group,
            "profile": request.profile,
            "enable_ml": request.enable_ml,
            "enable_llm": request.enable_llm,
        },
    )

    task = BenchmarkTask(
        benchmark_id=benchmark_id,
        endpoint=str(request.endpoint),
        label=request.label,
        group=request.group,
        profile=request.profile,
        enable_ml=request.enable_ml,
        enable_llm=request.enable_llm,
    )
    active_benchmark_tasks[benchmark_id] = task
    background_tasks.add_task(run_benchmark, benchmark_id, task)

    return {
        "benchmark_id": benchmark_id,
        "status": "pending",
        "message": "Benchmark task created successfully",
    }


async def run_benchmark(benchmark_id: str, task: BenchmarkTask):
    """Background task to execute benchmark."""
    try:
        db.update_benchmark_status(benchmark_id, "running")
        result = await asyncio.to_thread(task.run)
        db.save_benchmark_results(benchmark_id, result)
        db.update_benchmark_status(benchmark_id, "completed")
    except Exception as exc:
        db.update_benchmark_status(benchmark_id, "failed", error=str(exc))
        task.status = "failed"
        task.error = str(exc)


@app.get("/benchmarks")
async def list_benchmarks(
    limit: int = 50,
    offset: int = 0,
    label: Optional[str] = None,
    group: Optional[str] = None,
    days: Optional[int] = None,
):
    benchmarks = db.list_benchmarks(limit=limit, offset=offset, label=label, group=group, days=days)
    return {
        "benchmarks": benchmarks,
        "total": db.count_benchmarks(label=label, group=group, days=days),
        "limit": limit,
        "offset": offset,
    }


@app.get("/benchmarks/groups")
async def list_benchmark_groups(
    label: Optional[str] = None,
    group: Optional[str] = None,
    days: Optional[int] = None,
):
    return {
        "groups": db.summarize_benchmark_groups(label=label, group=group, days=days)
    }


@app.get("/benchmarks/{benchmark_id}/status", response_model=BenchmarkStatusResponse)
async def get_benchmark_status(benchmark_id: str):
    benchmark = db.get_benchmark(benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")

    progress = 0.0
    phase = None
    if benchmark_id in active_benchmark_tasks:
        progress = active_benchmark_tasks[benchmark_id].progress
        phase = active_benchmark_tasks[benchmark_id].current_phase
    elif benchmark["status"] == "completed":
        progress = 1.0
        phase = "Completed"

    return BenchmarkStatusResponse(
        id=benchmark["id"],
        status=benchmark["status"],
        endpoint=benchmark["endpoint"],
        label=benchmark.get("label"),
        group=benchmark.get("group"),
        progress=progress,
        start_time=benchmark["start_time"],
        end_time=benchmark.get("end_time"),
        error=benchmark.get("error"),
        phase=phase,
    )


@app.get("/benchmarks/{benchmark_id}")
async def get_benchmark_report(benchmark_id: str):
    benchmark = db.get_benchmark(benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    if benchmark["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Benchmark is not completed yet (status: {benchmark['status']})")

    result = db.get_benchmark_result(benchmark_id)
    if not result:
        raise HTTPException(status_code=404, detail="Benchmark results not found")
    return result


@app.get("/benchmarks/{benchmark_id}/export")
async def export_benchmark_report(
    benchmark_id: str,
    format: str = Query(default="json"),
):
    benchmark = db.get_benchmark(benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    result = db.get_benchmark_result(benchmark_id)
    if not result:
        raise HTTPException(status_code=404, detail="Benchmark results not found")

    if format == "md":
        content = render_benchmark_markdown(result["benchmark"])
        media_type = "text/markdown; charset=utf-8"
        extension = "md"
    else:
        content = to_pretty_json(result)
        media_type = "application/json"
        extension = "json"

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="dvga-benchmark-{benchmark_id}.{extension}"'
        },
    )


@app.delete("/benchmarks/{benchmark_id}")
async def delete_benchmark(benchmark_id: str):
    benchmark = db.get_benchmark(benchmark_id)
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    if benchmark["status"] == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running benchmark")
    db.delete_benchmark(benchmark_id)
    return {"message": "Benchmark deleted successfully"}


@app.get("/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    """
    Get list of all scans with pagination.
    """
    scans = db.list_scans(limit=limit, offset=offset)
    total = db.count_scans()
    
    return {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan and its results.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Cannot delete running scans
    if scan["status"] == "running":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running scan"
        )
    
    db.delete_scan(scan_id)
    
    return {"message": "Scan deleted successfully"}


@app.get("/stats")
async def get_stats():
    """
    Get overall statistics.
    """
    return db.get_statistics()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


def build_manual_reproduction(endpoint: str, request_override: Optional[Dict[str, Any]]) -> Optional[str]:
    if not request_override:
        return None
    payload = json.dumps(request_override)
    return (
        f"curl -X POST {endpoint} "
        '-H "Content-Type: application/json" '
        '-H "Accept: application/json" '
        f"-d '{payload}'"
    )


def _enrich_scan_report(result: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(result)
    findings = [dict(item) for item in enriched.get("findings", [])]
    enrich_finding_dicts(findings)
    enriched["findings"] = findings
    if not enriched.get("relationship_map"):
        enriched["relationship_map"] = build_relationship_map(enriched)
    return enriched
