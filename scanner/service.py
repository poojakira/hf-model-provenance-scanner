"""Authenticated admission API backed by the canonical HF scanner CLI."""

from __future__ import annotations

import hmac
import io
import json
import os
import re
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from scanner.cli import main as scanner_main

_REPO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_FAIL_ON = {"critical", "high", "medium", "low", "info"}

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


def _authorize(request: Request) -> None:
    expected = os.environ.get("API_KEY", "")
    if not expected:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
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
    if not os.environ.get("API_KEY"):
        raise HTTPException(status_code=503, detail="API_KEY is not configured")
    return {"status": "ready"}


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest, request: Request) -> ScanResponse:
    _authorize(request)
    _validate_target(payload)
    started = time.perf_counter()
    code, result = await run_in_threadpool(_scan_sync, payload)
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
        error=result.get("error"),
    )
