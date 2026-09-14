"""SENTINEL-X FastAPI application."""
from __future__ import annotations
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import iocs, pipeline, report
from .config import CASES, DEMO, MODELS, RETENTION_DAYS, STATIC


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    removed = pipeline.purge_expired()
    if removed:
        print(f"[sentinelx] retention: purged {removed} case(s) older than "
              f"{RETENTION_DAYS} days")
    yield


app = FastAPI(
    title="SENTINEL-X",
    description="Android banking-malware static analysis & intelligence platform",
    version="1.1.0",
    lifespan=lifespan,
)


def _load_case(case_id: str) -> dict[str, Any]:
    for path in CASES.glob("*.json"):
        case = json.loads(path.read_text())
        if case.get("case_id") == case_id or path.stem == case_id:
            return case
    for path in DEMO.glob("*.json"):
        case = json.loads(path.read_text())
        if case.get("case_id") == case_id:
            return case
    raise HTTPException(404, f"case {case_id} not found")


@app.get("/api/health")
def health() -> dict[str, Any]:
    metrics_path = MODELS / "metrics.json"
    return {
        "status": "ok",
        "model_loaded": (MODELS / "xgb.joblib").exists(),
        "model_metrics": (json.loads(metrics_path.read_text())
                          if metrics_path.exists() else None),
        "cached_cases": len(list(CASES.glob("*.json"))),
        "demo_cases": len(list(DEMO.glob("*.json"))),
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)) -> JSONResponse:
    # Held in memory only: the sample is never written to disk or executed.
    data = await file.read()
    try:
        pipeline.validate(data)
    except pipeline.IngestError as exc:
        raise HTTPException(400, str(exc))
    try:
        case = await run_in_threadpool(
            pipeline.analyse, data, None, file.filename or "sample.apk")
    except pipeline.ParseError as exc:
        raise HTTPException(422, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"ANALYSIS_FAILED: {exc}")
    return JSONResponse(case)


@app.get("/api/cases")
def list_cases() -> list[dict[str, Any]]:
    out = []
    for path in list(CASES.glob("*.json")) + list(DEMO.glob("*.json")):
        try:
            c = json.loads(path.read_text())
        except Exception:
            continue
        out.append({
            "case_id": c.get("case_id"),
            "filename": c.get("filename"),
            "verdict": c.get("classification", {}).get("verdict"),
            "severity": c.get("risk", {}).get("severity"),
            "score": c.get("risk", {}).get("composite_score"),
            "analysed_at": c.get("analysed_at"),
            "demo": path.parent.name == "demo",
        })
    return sorted(out, key=lambda d: d.get("analysed_at") or "", reverse=True)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    return _load_case(case_id)


@app.get("/api/cases/{case_id}/iocs.json")
def iocs_json(case_id: str) -> JSONResponse:
    bundle = iocs.build(_load_case(case_id))
    return JSONResponse(bundle, headers={
        "Content-Disposition": f'attachment; filename="iocs_{case_id[:8]}.json"'})


@app.get("/api/cases/{case_id}/iocs.csv")
def iocs_csv(case_id: str) -> Response:
    bundle = iocs.build(_load_case(case_id))
    return Response(iocs.to_csv(bundle), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="iocs_{case_id[:8]}.csv"'})


@app.get("/api/cases/{case_id}/report.pdf")
def report_pdf(case_id: str) -> Response:
    pdf = report.build_pdf(_load_case(case_id))
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition":
            f'attachment; filename="sentinelx_report_{case_id[:8]}.pdf"'})


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    path = STATIC / "favicon.ico"
    if path.exists():
        return FileResponse(path)
    return Response(status_code=204)


# Dashboard (mounted last so /api/* and /favicon.ico win).
if STATIC.exists():
    app.mount("/", StaticFiles(directory=str(STATIC), html=True), name="static")
