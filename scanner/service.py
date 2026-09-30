"""Authenticated admission API backed by the canonical HF scanner CLI."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import os
import re
import time
import uuid
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from scanner.cli import main as scanner_main

_REPO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_FAIL_ON = {"critical", "high", "medium", "low", "info"}
_SCAN_TIMEOUT_SECONDS = float(os.environ.get("SCAN_TIMEOUT_SECONDS", "120"))
_MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "4"))
_MAX_REQUEST_BYTES = int(os.environ.get("SCAN_MAX_REQUEST_BYTES", "16384"))
_RATE_LIMIT_RPM = int(os.environ.get("SCAN_RATE_LIMIT_RPM", "60"))
_request_log: dict[str, list[float]] = defaultdict(list)
if _SCAN_TIMEOUT_SECONDS <= 0:
    raise RuntimeError("SCAN_TIMEOUT_SECONDS must be positive")
if _MAX_CONCURRENT_SCANS < 1 or _MAX_CONCURRENT_SCANS > 64:
    raise RuntimeError("MAX_CONCURRENT_SCANS must be between 1 and 64")
if _MAX_REQUEST_BYTES < 1024 or _MAX_REQUEST_BYTES > 1024 * 1024:
    raise RuntimeError("SCAN_MAX_REQUEST_BYTES must be between 1024 and 1048576")
if _RATE_LIMIT_RPM < 1 or _RATE_LIMIT_RPM > 10000:
    raise RuntimeError("SCAN_RATE_LIMIT_RPM must be between 1 and 10000")
_scan_slots = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)

app = FastAPI(
    title="HF Model Provenance Admission Service",
    version="1.0.0",
    description="Resolve a model revision immutably, scan it, and return an admission decision.",
)


class ScanRequest(BaseModel):
    repo_id: str = Field(min_length=3, max_length=256)
    revision: str = Field(default="main", min_length=1, max_length=200)
    fail_on: str = Field(default="high")


class ScanResponse(BaseModel):
    scan_id: str
    decision: str
    exit_code: int
    duration_ms: float
    artifact_revision: str | None
    completeness: str
    risk: dict
    findings: list[dict]
    error: str | None = None


def _rate_key(request: Request) -> str:
    supplied = request.headers.get("X-API-Key", "")
    peer = request.client.host if request.client else "unknown"
    return hashlib.sha256(f"{peer}\0{supplied}".encode("utf-8")).hexdigest()[:32]


def _is_rate_limited(key: str) -> bool:
    now = time.time()
    cutoff = now - 60.0
    hits = [stamp for stamp in _request_log[key] if stamp > cutoff]
    if len(hits) >= _RATE_LIMIT_RPM:
        _request_log[key] = hits
        return True
    hits.append(now)
    _request_log[key] = hits
    if len(_request_log) > 10000:
        stale = [candidate for candidate, stamps in _request_log.items() if not stamps or stamps[-1] <= cutoff]
        for candidate in stale[:2000]:
            _request_log.pop(candidate, None)
    return False


@app.middleware("http")
async def _request_size_limit(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH"}:
        declared = request.headers.get("content-length")
        if declared:
            try:
                if int(declared) > _MAX_REQUEST_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        body = await request.body()
        if len(body) > _MAX_REQUEST_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


def _authorize(request: Request) -> None:
    expected = os.environ.get("API_KEY", "")
    if len(expected) < 32:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured with a sufficiently strong key",
        )
    supplied = request.headers.get("X-API-Key", "")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _validate_target(payload: ScanRequest) -> None:
    if not _REPO_ID.fullmatch(payload.repo_id):
        raise HTTPException(status_code=422, detail="repo_id must be exactly owner/model")
    if not _REVISION.fullmatch(payload.revision) or ".." in payload.revision:
        raise HTTPException(status_code=422, detail="invalid revision")
    if payload.fail_on.lower() not in _FAIL_ON:
        raise HTTPException(status_code=422, detail="invalid fail_on threshold")


def _scan_sync(payload: ScanRequest) -> tuple[int, dict]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    args = [
        payload.repo_id,
        "--mode",
        "remote",
        "--revision",
        payload.revision,
        "--format",
        "json",
        "--fail-on",
        payload.fail_on.lower(),
        "--enforce",
    ]
    token = os.environ.get("HF_TOKEN")
    if token:
        args.extend(["--token", token])

    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = int(scanner_main(args))

    raw = stdout.getvalue().strip()
    if not raw:
        return 2, {
            "error": stderr.getvalue().strip() or "scanner produced no JSON result",
            "completeness": "UNKNOWN",
            "risk": {},
            "findings": [],
            "artifact_revision": None,
        }
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return 2, {
            "error": "scanner output was not valid JSON",
            "completeness": "UNKNOWN",
            "risk": {},
            "findings": [],
            "artifact_revision": None,
        }
    if not isinstance(result, dict):
        return 2, {
            "error": "scanner output was not a JSON object",
            "completeness": "UNKNOWN",
            "risk": {},
            "findings": [],
            "artifact_revision": None,
        }
    return code, result


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "hf-model-provenance-admission"}


@app.get("/ready")
def ready() -> dict[str, str]:
    if len(os.environ.get("API_KEY", "")) < 32:
        raise HTTPException(status_code=503, detail="API_KEY must be at least 32 characters")
    return {
        "status": "ready",
        "max_concurrent_scans": str(_MAX_CONCURRENT_SCANS),
        "scan_timeout_seconds": str(_SCAN_TIMEOUT_SECONDS),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest, request: Request) -> ScanResponse:
    _authorize(request)
    if _is_rate_limited(_rate_key(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _validate_target(payload)
    started = time.perf_counter()
    try:
        async with _scan_slots:
            code, result = await asyncio.wait_for(
                run_in_threadpool(_scan_sync, payload),
                timeout=_SCAN_TIMEOUT_SECONDS,
            )
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Scanner execution timed out") from exc

    completeness = str(result.get("completeness", "UNKNOWN")).upper()

    if code == 0 and completeness == "COMPLETE":
        decision = "ALLOW"
    elif code == 1:
        decision = "BLOCK"
    else:
        decision = "ERROR"

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        decision=decision,
        exit_code=code,
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        artifact_revision=result.get("artifact_revision"),
        completeness=completeness,
        risk=result.get("risk") or {},
        findings=result.get("findings") or [],
        error="scan_failed" if result.get("error") else None,
    )
