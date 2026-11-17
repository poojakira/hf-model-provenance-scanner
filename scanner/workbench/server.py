"""Loopback-only, keyless local workbench. Remote admission service is unchanged."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import BinaryIO, cast

from scanner.cli import SCANNER_VERSION

MAX_BODY = 12 * 1024**2
LIMITS = {
    "files": 2,
    "file_bytes": 4 * 1024**2,
    "request_bytes": MAX_BODY,
    "wall_seconds": 8,
    "cpu_seconds": 4,
    "memory_bytes": 384 * 1024**2,
    "concurrency": 1,
    "structure_items": 4096,
    "response_bytes": 4 * 1024**2,
}
ASSETS = Path(__file__).parent


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def provenance() -> dict:
    root = Path(__file__).resolve().parents[2]

    def git(*args):
        return (
            subprocess.check_output(
                [shutil.which("git") or "/usr/bin/git", "-C", str(root), *args],
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            .decode()
            .strip()
        )

    try:
        if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("Installed package is outside its source repository")
        git("ls-files", "--error-unmatch", "scanner/workbench/server.py")
        commit = git("rev-parse", "HEAD")
        state = "DIRTY" if git("status", "--porcelain", "--untracked-files=all") else "CLEAN"
    except (OSError, ValueError, subprocess.SubprocessError):
        commit, state = "UNKNOWN", "UNKNOWN"
    rule_dir = root / "scanner"
    paths = sorted([*rule_dir.rglob("*.py"), *(rule_dir / "data").glob("*.json")])
    rule_sources = {str(p.relative_to(rule_dir)): sha(p.read_bytes()) for p in paths}
    return {
        "app": "AI Model Trust Inspector",
        "version": SCANNER_VERSION,
        "local_api_version": "1",
        "remote_admission_api": "separate existing 1.0.0 service",
        "commit": commit,
        "source_state": state,
        "rule_sources": rule_sources,
        "rule_set_sha256": sha(json.dumps(rule_sources, sort_keys=True).encode()),
    }


def validate(request: dict) -> None:
    if not isinstance(request, dict) or set(request) != {"files"}:
        raise ValueError("Expected only a files array")
    files = request["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 2:
        raise ValueError("Select one or two files")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"name", "data"}:
            raise ValueError("Each file needs only name and base64 data")
        if not isinstance(item["name"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", item["name"]
        ):
            raise ValueError("Use a plain ASCII filename, no paths (maximum 120 characters)")
        if not isinstance(item["data"], str) or len(item["data"]) > 4 * (
            (LIMITS["file_bytes"] + 2) // 3
        ):
            raise ValueError("File exceeds 4 MiB")
        data = base64.b64decode(item["data"], validate=True)
        if not 1 <= len(data) <= LIMITS["file_bytes"]:
            raise ValueError("Empty or oversized file")


def _capture(process: subprocess.Popen, payload: bytes, timeout: float) -> tuple[bytes, bytes]:
    """Read bounded pipes while writing input; kill and reap the entire group on failure."""
    deadline = time.monotonic() + timeout
    chunks = {"out": bytearray(), "err": bytearray()}
    pending = memoryview(payload)
    selector = selectors.DefaultSelector()
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    streams = [process.stdin, process.stdout, process.stderr]
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "in")
        selector.register(process.stdout, selectors.EVENT_READ, "out")
        selector.register(process.stderr, selectors.EVENT_READ, "err")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            for key, _ in selector.select(remaining):
                stream, kind = cast(BinaryIO, key.fileobj), key.data
                if kind == "in":
                    try:
                        sent = os.write(stream.fileno(), pending[:65536]) if pending else 0
                        pending = pending[sent:]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    cap = LIMITS["response_bytes"] if kind == "out" else 65536
                    if len(chunks[kind]) + len(chunk) > cap:
                        raise ValueError("Worker output limit exceeded")
                    chunks[kind].extend(chunk)
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return bytes(chunks["out"]), bytes(chunks["err"])
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        raise
    finally:
        selector.close()
        for stream in streams:
            stream.close()


def run_worker(request: dict, timeout: float = 8) -> dict:
    # Fixed interpreter/module, fixed cwd, scrubbed environment; no operator command/paths.
    payload = json.dumps(request, allow_nan=False).encode()
    try:
        with subprocess.Popen(
            [sys.executable, "-m", "scanner.workbench.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            cwd=str(Path(__file__).resolve().parents[2]),
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"},
        ) as process:
            output, _ = _capture(process, payload, timeout)
            if process.returncode != 0:
                return {
                    "status": "UNKNOWN",
                    "error": "Worker failed/resource limit/containment unavailable",
                    "files": [],
                }
        return json.loads(output)
    except subprocess.TimeoutExpired:
        return {
            "status": "UNKNOWN",
            "error": "Worker timed out and process group was terminated",
            "files": [],
        }
    except (OSError, ValueError):
        return {
            "status": "UNKNOWN",
            "error": "Worker unavailable/invalid response/output limit",
            "files": [],
        }


def report(request: dict, source: dict) -> dict:
    started = utc()
    result = run_worker(request)
    files = result.get("files", [])
    comparison = None
    if len(files) == 2:
        left, right = files
        comparison = {
            "bytes_equal": left["sha256"] == right["sha256"],
            "structures_equal": left.get("structure_sha256") == right.get("structure_sha256")
            if all("structure_sha256" in f for f in files)
            else None,
            "format_equal": left.get("format") == right.get("format")
            if all("format" in f for f in files)
            else None,
            "meaning": "Hashes and static structures only; no semantic/behavioral equivalence claim",
        }
        lh, rh = (f.get("structures", {}).get("header") for f in files)
        if lh is not None and rh is not None:
            comparison["metadata_equal"] = lh.get("__metadata__") == rh.get("__metadata__")
            comparison["tensor_names_added"] = sorted(set(rh) - set(lh) - {"__metadata__"})
            comparison["tensor_names_removed"] = sorted(set(lh) - set(rh) - {"__metadata__"})
    inputs = [
        {
            "name": f["name"],
            "size": len(base64.b64decode(f["data"], validate=True)),
            "sha256": sha(base64.b64decode(f["data"], validate=True)),
        }
        for f in request["files"]
    ]
    return {
        "schema_version": "1",
        "run_id": str(uuid.uuid4()),
        "started_utc": started,
        "finished_utc": utc(),
        "source": source,
        "limits": LIMITS,
        "config_sha256": sha(json.dumps(LIMITS, sort_keys=True).encode()),
        "input_manifest": inputs,
        "input_manifest_sha256": sha(json.dumps(inputs, sort_keys=True).encode()),
        "request_sha256": sha(json.dumps(request, sort_keys=True).encode()),
        "assessment": "UNKNOWN"
        if result.get("error") or any(f["status"] == "UNKNOWN" for f in files)
        else "STATIC_INSPECTION_ONLY",
        "comparison": comparison,
        "result": result,
        "limitations": [
            "No model execution, deserialization, extraction or downloads.",
            "No trusted publisher/signature or training lineage supplied; origin UNKNOWN.",
            "No patterns found does not prove safety or absence of backdoors.",
            "GGUF tensor payload/quantization validation and semantic behavior are NOT VERIFIED.",
            "Linux syscall containment is not a VM/container; kernel vulnerabilities remain outside scope.",
            "Inputs live only in bounded process memory; no disk retention. Memory is not cryptographically erased.",
        ],
    }


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address):
        self.gate = threading.BoundedSemaphore(8)
        self.scan_gate = threading.BoundedSemaphore(1)
        self.token = secrets.token_urlsafe(32)
        self.source = provenance()
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.gate.acquire(blocking=False):
            cast(socket.socket, request).close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.gate.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.gate.release()


class Handler(BaseHTTPRequestHandler):
    @property
    def inspector(self) -> Server:
        return cast(Server, self.server)

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format: str, *args):
        pass  # No filenames, contents or token in logs.

    def send(self, code: int, body: bytes, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def error(self, code: int, message: str):
        self.send(code, json.dumps({"status": "UNKNOWN", "error": message}).encode())

    def trusted_host(self) -> bool:
        return self.headers.get("Host") in {
            f"127.0.0.1:{self.inspector.server_port}",
            f"localhost:{self.inspector.server_port}",
        }

    def do_GET(self):
        if not self.trusted_host():
            self.error(403, "Loopback Host required")
            return
        if self.path == "/api/health":
            self.send(
                200,
                json.dumps(
                    {
                        "status": "ready",
                        "source": self.inspector.source,
                        "limits": LIMITS,
                        "csrf_token": self.inspector.token,
                    }
                ).encode(),
            )
        elif self.path in ("/", "/app.js", "/style.css"):
            name, mime = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
            }[self.path]
            self.send(200, (ASSETS / name).read_bytes(), mime)
        else:
            self.error(404, "Unknown route")

    def do_POST(self):
        expected = {
            f"http://127.0.0.1:{self.inspector.server_port}",
            f"http://localhost:{self.inspector.server_port}",
        }
        if (
            not self.trusted_host()
            or self.headers.get("Origin") not in expected
            or not hmac.compare_digest(
                self.headers.get("X-Inspector-Token", ""), self.inspector.token
            )
        ):
            self.error(403, "Same-origin session required")
            return
        if self.path != "/api/inspect":
            self.error(404, "Unknown route")
            return
        if self.headers.get("Content-Type") != "application/json" or self.headers.get(
            "Transfer-Encoding"
        ):
            self.error(415, "Use bounded application/json with Content-Length")
            return
        if not self.inspector.scan_gate.acquire(blocking=False):
            self.error(429, "One scan at a time; retry after current scan")
            return
        try:
            raw_length = self.headers.get_all("Content-Length", [])
            if (
                len(raw_length) != 1
                or not raw_length[0].isdigit()
                or not 1 <= int(raw_length[0]) <= MAX_BODY
            ):
                self.error(413, "Request size missing/invalid/exceeds 12 MiB")
                return
            remaining, chunks = int(raw_length[0]), []
            deadline = time.monotonic() + 5
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise TimeoutError("Upload deadline")
                self.connection.settimeout(budget)
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    raise ValueError("Incomplete request")
                chunks.append(chunk)
                remaining -= len(chunk)
            request = json.loads(b"".join(chunks))
            validate(request)
            self.send(200, json.dumps(report(request, provenance())).encode())
        except (ValueError, TypeError, KeyError, RecursionError):
            self.error(400, "Invalid request or filename/base64/size constraints")
        except TimeoutError:
            self.error(408, "Upload timed out")
        finally:
            self.inspector.scan_gate.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8763)
    args = parser.parse_args()
    with Server(("127.0.0.1", args.port)) as server:
        print(
            f"AI Model Trust Inspector {SCANNER_VERSION}: http://127.0.0.1:{server.server_port}",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
