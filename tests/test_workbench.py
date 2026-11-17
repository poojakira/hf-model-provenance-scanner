"""Actual bounded worker/API regressions; fixtures are synthetic, never loaded."""

import base64
import hashlib
import http.client
import json
import os
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from scanner.workbench.server import LIMITS, Server, provenance, report, run_worker, validate
from scanner.workbench.worker import MAX_FILE, structure


def item(name, data):
    return {"name": name, "data": base64.b64encode(data).decode()}


def st(metadata=None, payload=b"\0\0\0\0", shape=None, extra=None):
    header = {
        "weight": {
            "dtype": "F32",
            "shape": [1] if shape is None else shape,
            "data_offsets": [0, len(payload)],
        }
    }
    if metadata is not None:
        header["__metadata__"] = metadata
    if extra:
        header.update(extra)
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + payload


def scan(name, data):
    return run_worker({"files": [item(name, data)]})["files"][0]


def test_real_existing_engine_source_and_nonexecution(tmp_path):
    sentinel = tmp_path / "must-not-exist"
    source = f'import os\nos.system("touch {sentinel}")\n'.encode()
    result = scan("loader.py", source)
    assert result["status"] == "CONCERNS"
    assert any(f["rule_id"] == "HFS-001" and f["line_number"] == 2 for f in result["findings"])
    assert not sentinel.exists()
    assert result["sha256"] == hashlib.sha256(source).hexdigest()


def test_actual_pickle_opcodes_and_no_execution(tmp_path):
    sentinel = tmp_path / "pickle-executed"
    data = b"cos\nsystem\n(S'touch " + str(sentinel).encode() + b"'\ntR."
    result = scan("payload.pkl", data)
    assert result["status"] == "CONCERNS"
    assert any(f["rule_id"].startswith("HFS-") for f in result["findings"])
    assert any(
        o["opcode"] == "GLOBAL" and o["offset"] == 0 for o in result["structures"]["opcodes"]
    )
    assert not sentinel.exists()


def test_safetensors_compare_metadata_and_raw_bytes():
    a, b = st({"author": "synthetic"}), st({"author": "https://example.invalid/synthetic"})
    result = report({"files": [item("a.safetensors", a), item("b.safetensors", b)]}, provenance())
    assert result["comparison"]["bytes_equal"] is False
    assert result["comparison"]["metadata_equal"] is False
    assert result["result"]["files"][0]["structures"]["fingerprint"]["tensor_count"] == 1
    assert result["result"]["files"][1]["findings"]
    assert result["source"]["rule_sources"] and result["config_sha256"]
    assert result["request_sha256"] and result["input_manifest_sha256"]


@pytest.mark.parametrize(
    "name,data",
    [
        ("x.safetensors", b"no"),
        ("x.safetensors", struct.pack("<Q", 2**63)),
        ("x.safetensors", st(shape=[2**30, 2**30])),
        ("x.safetensors", st() + b"cos\nsystem\n"),
        ("x.safetensors", struct.pack("<Q", 13) + b'{"a":1,"a":2}'),
        (
            "x.safetensors",
            st(extra={"bad": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}),
        ),
        ("x.pkl", b"\x80\x04N." + b"trailing"),
        ("x.pkl", b"\x80\x04\x8d" + b"\xff" * 8),
        ("x.pt", b"PK\x03\x04archive"),
        ("x.pkl", b"GGUF" + b"\0" * 32),
        ("x.gguf", b"GGUF" + struct.pack("<IQQ", 3, 0, 2**63)),
        ("x.gguf", b"GGUF" + struct.pack("<IQQ", 3, 1, 1)),
        ("x.gguf", b"GGUF" + struct.pack("<IQQ", 1, 0, 0)),
        ("x.py", b"\0bad"),
        ("x.py", b"def incomplete("),
        ("x.py", b"\xff\xfe"),
        ("x.onnx", b"unsupported"),
    ],
)
def test_hostile_or_unsupported_never_green(name, data):
    result = scan(name, data)
    assert result["status"] == "UNKNOWN" and result["error"]


def test_valid_gguf_real_metadata_engine():
    key, value = b"custom.command", b"os.system('synthetic')"
    data = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)
    data += (
        struct.pack("<Q", len(key))
        + key
        + struct.pack("<I", 8)
        + struct.pack("<Q", len(value))
        + value
    )
    result = scan("x.gguf", data)
    assert result["format"] == "gguf" and result["findings"]
    assert result["structures"]["metadata"]["custom.command"]["offset"] == 24


def test_nested_gguf_arrays_rejected():
    data = b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 1) + b"x"
    data += struct.pack("<IIQ", 9, 9, 2)
    assert scan("nested.gguf", data)["status"] == "UNKNOWN"


def test_timeout_is_unknown_and_recovery_real():
    assert run_worker({"files": [item("a.py", b"pass")]}, timeout=0.00001)["status"] == "UNKNOWN"
    assert scan("a.py", b"pass")["status"] == "NO_PATTERN_FOUND"


def test_seccomp_denies_files_network_execution_and_fork():
    script = """
import os, socket, subprocess
from scanner.workbench.containment import seal
seal()
checks = [lambda: open('/etc/passwd'), lambda: socket.socket(), lambda: os.fork(),
          lambda: os.execv('/bin/true', ['/bin/true'])]
for check in checks:
    try:
        check()
    except PermissionError:
        continue
    raise SystemExit('Containment allowed a forbidden operation')
print('all denied')
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    assert b"all denied" in result.stdout


@pytest.mark.parametrize(
    "invalid_request",
    [
        {"files": []},
        {"files": [item("../evil.py", b"pass")]},
        {"files": [item("/tmp/a.py", b"pass")]},
        {"files": [item("a.py", b"")]},
        {"files": [item("a.py", b"pass")] * 3},
        {"files": [{"name": "a.py", "data": "!!!!"}]},
        {"files": [item("a.py", b"x" * (MAX_FILE + 1))]},
        {"files": [item("a.py", b"pass")], "url": "http://169.254.169.254"},
    ],
)
def test_request_restrictions(invalid_request):
    with pytest.raises(ValueError):
        validate(invalid_request)


@pytest.fixture
def api():
    server = Server(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


def call(api, method="GET", path="/api/health", body=None, headers=None):
    client = http.client.HTTPConnection("127.0.0.1", api.server_port, timeout=15)
    client.request(method, path, body=body, headers=headers or {})
    response = client.getresponse()
    result = response.status, response.getheaders(), response.read()
    client.close()
    return result


def auth(api):
    return {
        "Origin": f"http://127.0.0.1:{api.server_port}",
        "X-Inspector-Token": api.token,
        "Content-Type": "application/json",
    }


def test_http_real_upload_retry_export_contract(api):
    code, headers, raw = call(api)
    assert code == 200 and json.loads(raw)["source"]["version"] == "0.3.0"
    assert "no-store" in dict(headers)["Cache-Control"]
    for content in (b"pass", b'import os\nos.system("synthetic")'):
        code, _, raw = call(
            api, "POST", "/api/inspect", json.dumps({"files": [item("a.py", content)]}), auth(api)
        )
        assert (
            code == 200
            and json.loads(raw)["result"]["files"][0]["sha256"]
            == hashlib.sha256(content).hexdigest()
        )
    assert json.loads(raw)["result"]["files"][0]["findings"]
    assert call(api, path="/../../etc/passwd")[0] == 404


def test_http_same_origin_host_token_and_concurrency(api):
    body = json.dumps({"files": [item("a.py", b"pass")]})
    assert call(api, "POST", "/api/inspect", body)[0] == 403
    headers = auth(api)
    headers["Origin"] = "http://evil.example"
    assert call(api, "POST", "/api/inspect", body, headers)[0] == 403
    assert call(api, headers={"Host": "evil.example"})[0] == 403
    api.scan_gate.acquire()
    try:
        assert call(api, "POST", "/api/inspect", body, auth(api))[0] == 429
    finally:
        api.scan_gate.release()
    headers = auth(api)
    headers["Content-Length"] = str(LIMITS["request_bytes"] + 1)
    assert call(api, "POST", "/api/inspect", b"", headers)[0] == 413


def test_bounded_malformed_corpus_and_reproducibility():
    # Deterministic bounded parser corruption, not an accuracy benchmark.
    for index in range(30):
        data = hashlib.sha256(str(index).encode()).digest()[: index + 1]
        try:
            structure("a.safetensors", data)
        except (ValueError, struct.error):
            pass
        else:
            pytest.fail("Malformed header accepted")
    request = {"files": [item("a.safetensors", st())]}
    assert run_worker(request) == run_worker(request)


def test_installer_never_removes_existing_directory(tmp_path):
    sentinel = tmp_path / "keep"
    sentinel.write_text("preserve")
    result = subprocess.run(
        ["/bin/bash", "install.sh"],
        env={**os.environ, "HF_SCANNER_DIR": str(tmp_path)},
        capture_output=True,
    )
    assert result.returncode != 0 and sentinel.read_text() == "preserve"
    assert "Refusing to replace" in result.stderr.decode()
    assert "rm -rf" not in Path("install.sh").read_text()


def test_static_structure_object_evidence_and_parser_boundaries():
    # Direct pure parsing supplements separately verified seccomp worker paths.
    from scanner.workbench.worker import inspect

    for name, data in [
        ("a.safetensors", st({"author": "synthetic"})),
        ("a.pkl", b"\x80\x04N."),
        ("a.py", b"weights=[1,2]\n"),
        ("a.gguf", b"GGUF" + struct.pack("<IQQ", 3, 0, 0)),
    ]:
        direct = inspect(item(name, data))
        assert json.loads(json.dumps(direct, default=lambda value: value.value)) == scan(name, data)
        assert direct["structures"] and direct["structure_sha256"]
    assert inspect(item("a.py", b""))["status"] == "UNKNOWN"
    with pytest.raises(ValueError):
        structure("a.gguf", b"wrongmagic")
    for raw in [
        st(shape=[-1]),
        st(shape=[True]),
        st(shape="bad"),
        st(extra={"bad": 4}),
        st(metadata={"wrong": 4}),
        struct.pack("<Q", 2) + b"[]",
        st(payload=b"\0"),
        b"PK\x03\x04",
        b"invalid",
    ]:
        assert inspect(item("a.safetensors", raw))["status"] == "UNKNOWN"
    assert inspect(item("a.py", b"def bad("))["error"]
    assert inspect(item("a.zip", b"bad"))["status"] == "UNKNOWN"
    assert inspect(item("a.pkl", b"N.trailing"))["status"] == "UNKNOWN"
    assert (
        inspect(item("a.gguf", b"GGUF" + struct.pack("<IQQ", 3, 0, 2**63)))["status"] == "UNKNOWN"
    )


@pytest.mark.parametrize(
    "code,exception",
    [
        ("import os\nwhile True: os.write(1,b'x'*65536)", ValueError),
        ("import os\nwhile True: os.write(2,b'x'*65536)", ValueError),
        ("while True: pass", subprocess.TimeoutExpired),
    ],
)
def test_parent_bounds_real_flooding_timeout_and_reaps(code, exception):
    from scanner.workbench.server import _capture

    with subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        with pytest.raises(exception):
            _capture(process, b"", 0.4)
        assert process.poll() is not None
    assert scan("recovery.py", b"pass")["status"] == "NO_PATTERN_FOUND"


def gguf_metadata(kind, raw):
    return (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 1)
        + struct.pack("<Q", 1)
        + b"x"
        + struct.pack("<I", kind)
        + raw
    )


@pytest.mark.parametrize(
    "data",
    [
        b"GGUF" + struct.pack("<IQQ", 3, 0, 0) + b"N.",
        gguf_metadata(4, b""),
        gguf_metadata(7, b"\2"),
        gguf_metadata(6, struct.pack("<f", float("nan"))),
        gguf_metadata(12, struct.pack("<d", float("inf"))),
        gguf_metadata(8, struct.pack("<Q", 1) + b"\xff"),
        gguf_metadata(8, struct.pack("<Q", 99) + b"x"),
        gguf_metadata(9, struct.pack("<IQ", 9, 1)),
        gguf_metadata(9, struct.pack("<IQ", 4, 4097)),
        gguf_metadata(9, struct.pack("<IQ", 4, 1)),
    ],
)
def test_gguf_polyglot_nonfinite_and_truncation_direct_and_isolated(data):
    from scanner.workbench.worker import inspect

    assert inspect(item("x.gguf", data))["status"] == "UNKNOWN"
    assert scan("x.gguf", data)["status"] == "UNKNOWN"


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_safetensors_nonfinite_json_rejected(number):
    from scanner.workbench.worker import inspect

    header = ('{"extra":' + number + "}").encode()
    data = struct.pack("<Q", len(header)) + header
    assert inspect(item("x.safetensors", data))["status"] == "UNKNOWN"
    assert scan("x.safetensors", data)["status"] == "UNKNOWN"


def test_gguf_bounded_metadata_types_and_tensor_descriptor():
    from scanner.workbench.worker import inspect

    for kind, raw in [
        (4, struct.pack("<I", 7)),
        (7, b"\1"),
        (8, struct.pack("<Q", 2) + b"ok"),
        (9, struct.pack("<IQII", 4, 2, 1, 2)),
        (6, struct.pack("<f", 1.5)),
    ]:
        result = inspect(item("x.gguf", gguf_metadata(kind, raw)))
        assert (
            result["status"] != "UNKNOWN" and result["structures"]["metadata"]["x"]["offset"] == 24
        )
    data = b"GGUF" + struct.pack("<IQQ", 3, 1, 0)
    data += struct.pack("<Q", 1) + b"w" + struct.pack("<IQIQ", 1, 1, 0, 0)
    result = inspect(item("x.gguf", data))
    assert result["structures"]["tensors"][0]["name"] == "w"
    assert "not validated" in result["structures"]["limitation"]


def test_assets_and_bad_contract_recover(api):
    for path, content_type in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/style.css", "text/css"),
    ]:
        code, headers, raw = call(api, path=path)
        assert code == 200 and content_type in dict(headers)["Content-Type"] and raw
    headers = auth(api)
    headers["Content-Type"] = "text/plain"
    assert call(api, "POST", "/api/inspect", b"bad", headers)[0] == 415
    assert call(api, "POST", "/api/missing", b"bad", auth(api))[0] == 404
    assert call(api, "POST", "/api/inspect", b"bad", auth(api))[0] == 400
    assert call(api, "POST", "/api/inspect", b'{"files":[]}', auth(api))[0] == 400
    assert call(api)[0] == 200


def test_installed_location_cannot_inherit_unrelated_git(tmp_path, monkeypatch):
    import shutil
    import subprocess

    from scanner.workbench import server

    git = shutil.which("git")
    assert git is not None
    project = tmp_path / "unrelated"
    project.mkdir()
    subprocess.run([git, "init", "-q", str(project)], check=True)
    subprocess.run([git, "-C", str(project), "config", "user.name", "Synthetic test"], check=True)
    subprocess.run(
        [git, "-C", str(project), "config", "user.email", "synthetic@example.invalid"],
        check=True,
    )
    (project / "unrelated.txt").write_text("Unrelated synthetic repository\n")
    subprocess.run([git, "-C", str(project), "add", "unrelated.txt"], check=True)
    subprocess.run(
        [git, "-C", str(project), "commit", "-qm", "Synthetic unrelated history"], check=True
    )
    package = project / ".venv/lib/site-packages/scanner/workbench"
    package.mkdir(parents=True)
    (package / "server.py").write_text("# Synthetic installed location\n")
    monkeypatch.setattr(server, "__file__", str(package / "server.py"))
    result = server.provenance()
    assert result["commit"] == result["source_state"] == "UNKNOWN"
