"""Authenticated admission API backed by the canonical HF scanner CLI."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from scanner.cli import main as scanner_main

logger = logging.getLogger(__name__)

_REPO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_FAIL_ON = {"critical", "high", "medium", "low", "info"}
_SCAN_TIMEOUT_SECONDS = float(os.environ.get("SCAN_TIMEOUT_SECONDS", "120"))
_MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "4"))
_MAX_REQUEST_BYTES = int(os.environ.get("SCAN_MAX_REQUEST_BYTES", "16384"))
_RATE_LIMIT_RPM = int(os.environ.get("SCAN_RATE_LIMIT_RPM", "60"))
_request_log: dict[str, list[float]] = defaultdict(list)
_RATE_KEY_SECRET = os.urandom(32)
if not math.isfinite(_SCAN_TIMEOUT_SECONDS) or _SCAN_TIMEOUT_SECONDS <= 0:
    raise RuntimeError("SCAN_TIMEOUT_SECONDS must be positive")
if _MAX_CONCURRENT_SCANS < 1 or _MAX_CONCURRENT_SCANS > 64:
    raise RuntimeError("MAX_CONCURRENT_SCANS must be between 1 and 64")
if _MAX_REQUEST_BYTES < 1024 or _MAX_REQUEST_BYTES > 1024 * 1024:
    raise RuntimeError("SCAN_MAX_REQUEST_BYTES must be between 1024 and 1048576")
if _RATE_LIMIT_RPM < 1 or _RATE_LIMIT_RPM > 10000:
    raise RuntimeError("SCAN_RATE_LIMIT_RPM must be between 1 and 10000")
_scanner_output_lock = threading.Lock()
_scan_slots = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)

app = FastAPI(
    title="HF Model Provenance Admission Service",
    version="1.0.0",
    description="Resolve a model revision immutably, scan it, and return an admission decision.",
)


class BodySizeLimitMiddleware:
    """Bound bytes from the ASGI stream, including chunked bodies, before parsing."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > _MAX_REQUEST_BYTES:
                response = JSONResponse(
                    status_code=413, content={"detail": "Request body too large"}
                )
                return await response(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        pending = True

        async def replay():
            nonlocal pending
            if pending:
                pending = False
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


app.add_middleware(BodySizeLimitMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # Pydantic's default response includes the rejected input, which may contain secrets.
    return JSONResponse(status_code=422, content={"detail": "Invalid request payload"})


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
    material = f"{peer}\0{supplied}".encode("utf-8")
    return hmac.new(_RATE_KEY_SECRET, material, hashlib.sha256).hexdigest()[:32]


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
        stale = [
            candidate
            for candidate, stamps in _request_log.items()
            if not stamps or stamps[-1] <= cutoff
        ]
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
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body too large"}
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _authorize(request: Request) -> None:
    expected = os.environ.get("API_KEY", "")
    if len(expected) < 32:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured with a sufficiently strong key",
        )
    supplied = request.headers.get("X-API-Key", "")
    if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _validate_target(payload: ScanRequest) -> None:
    if not _REPO_ID.fullmatch(payload.repo_id):
        raise HTTPException(status_code=422, detail="repo_id must be exactly owner/model")
    if not _REVISION.fullmatch(payload.revision) or ".." in payload.revision:
        raise HTTPException(status_code=422, detail="invalid revision")
    allowed = {
        repo.strip() for repo in os.environ.get("SCAN_ALLOWED_REPOS", "").split(",") if repo.strip()
    }
    if os.environ.get("HF_TOKEN") and not allowed:
        raise HTTPException(
            status_code=503, detail="Private model access requires a repository allowlist"
        )
    if allowed and payload.repo_id not in allowed:
        raise HTTPException(status_code=403, detail="Repository access denied")
    if payload.fail_on.lower() not in _FAIL_ON:
        raise HTTPException(status_code=422, detail="invalid fail_on threshold")


_active_jobs: set[asyncio.Task] = set()


async def _run_bounded(function, argument, slots, timeout):
    # A timed-out thread keeps running. Retain its slot until it actually exits.
    # Reject saturation instead of creating an unbounded queue of requests.
    if slots.locked():
        raise HTTPException(status_code=503, detail="Service busy")
    await slots.acquire()

    async def work():
        try:
            return await run_in_threadpool(function, argument)
        finally:
            slots.release()

    task = asyncio.create_task(work())
    _active_jobs.add(task)

    def finished(job):
        _active_jobs.discard(job)
        if not job.cancelled():
            job.exception()  # Retrieve failures after an HTTP timeout/disconnect.

    task.add_done_callback(finished)
    return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)


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

    # stdout/stderr redirection is global process state; concurrent scans must serialize it.
    with _scanner_output_lock, redirect_stdout(stdout), redirect_stderr(stderr):
        code = int(scanner_main(args))

    raw = stdout.getvalue().strip()
    if not raw:
        stderr_text = stderr.getvalue().strip()
        if stderr_text:
            logger.warning("Scanner produced no JSON result")
        return 2, {
            "error": "scanner execution failed",
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
        code, result = await _run_bounded(_scan_sync, payload, _scan_slots, _SCAN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Scanner execution timed out") from exc
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Scanner execution failed") from None

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
