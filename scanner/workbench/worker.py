"""Static engines only. No uploaded imports, unpickling, extraction or model loading."""

import ast
import base64
import hashlib
import io
import json
import math
import pickletools
import struct
import sys
from dataclasses import asdict
from enum import Enum

from scanner.analyzer.gguf_scanner import _read_gguf_string, _read_gguf_value
from scanner.analyzer.weight_fingerprint import DTYPE_SIZES, fingerprint_file
from scanner.cli import analyze_binary_file, analyze_source_file
from scanner.workbench.containment import seal

MAX_FILE = 4 * 1024**2
MAX_ITEMS = 4096


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"Non-finite JSON number: {value}")

    value = json.loads(data, object_pairs_hook=pairs, parse_constant=reject_constant)

    def finite(node):
        if isinstance(node, float) and not math.isfinite(node):
            raise ValueError("Non-finite JSON number")
        if isinstance(node, dict):
            for child in node.values():
                finite(child)
        elif isinstance(node, list):
            for child in node:
                finite(child)

    finite(value)
    return value


def gguf_string(data: bytes, pos: int) -> tuple[str, int]:
    length = struct.unpack_from("<Q", data, pos)[0]
    if length > 1024 * 1024 or pos + 8 + length > len(data):
        raise ValueError("Truncated/oversized GGUF string")
    data[pos + 8 : pos + 8 + length].decode("utf-8", errors="strict")
    return _read_gguf_string(data, pos)


def gguf_value(data: bytes, pos: int, kind: int) -> tuple:
    if kind == 8:
        return gguf_string(data, pos)
    if kind == 9:
        element, count = struct.unpack_from("<IQ", data, pos)
        if element == 9 or count > MAX_ITEMS:
            raise ValueError("Nested/oversized GGUF arrays unsupported")
        pos += 12
        values = []
        for _ in range(count):
            value, pos = gguf_value(data, pos, element)
            values.append(value)
        return values, pos
    sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
    if kind not in sizes or pos + sizes[kind] > len(data):
        raise ValueError("Unknown/truncated GGUF value")
    if kind == 7 and data[pos] not in (0, 1):
        raise ValueError("Invalid GGUF boolean")
    value, end = _read_gguf_value(data, pos, kind)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite GGUF metadata unsupported")
    return value, end


def structure(name: str, data: bytes) -> tuple[str, dict]:
    suffix = name.rsplit(".", 1)[-1].lower()
    if data.startswith(b"PK"):
        raise ValueError("Archives/PyTorch ZIP are unsupported; no decompression is performed")
    if suffix == "safetensors":
        if len(data) < 8:
            raise ValueError("Truncated safetensors header")
        size = struct.unpack_from("<Q", data)[0]
        if not 2 <= size <= min(len(data) - 8, 1024 * 1024):
            raise ValueError("Invalid/oversized safetensors header")
        header = strict_json(data[8 : 8 + size])
        if not isinstance(header, dict) or len(header) > MAX_ITEMS:
            raise ValueError("Invalid/oversized tensor map")
        end = 0
        regions = []
        for key, value in header.items():
            if key == "__metadata__":
                if not isinstance(value, dict) or not all(
                    isinstance(v, str) for v in value.values()
                ):
                    raise ValueError("Metadata must map strings to strings")
                continue
            if not isinstance(value, dict):
                raise ValueError("Invalid tensor descriptor")
            shape, offsets, dtype = (
                value.get("shape"),
                value.get("data_offsets"),
                value.get("dtype"),
            )
            if (
                not isinstance(shape, list)
                or len(shape) > 32
                or not all(type(d) is int and 0 <= d <= 2**31 for d in shape)
            ):
                raise ValueError("Invalid/oversized dimensions")
            count = 1
            for dim in shape:
                count *= dim
                if count > MAX_FILE:
                    raise ValueError("Tensor dimensions exceed local inspection limit")
            if (
                dtype not in DTYPE_SIZES
                or not isinstance(offsets, list)
                or len(offsets) != 2
                or not all(type(v) is int for v in offsets)
            ):
                raise ValueError("Invalid dtype/offsets")
            start, stop = offsets
            if (
                not 0 <= start <= stop <= len(data) - 8 - size
                or stop - start != count * DTYPE_SIZES[dtype]
            ):
                raise ValueError("Tensor byte range/shape mismatch")
            regions.append((start, stop))
            end = max(end, stop)
        previous = 0
        for start, stop in sorted(regions):
            if start != previous:
                raise ValueError("Overlapping or noncontiguous tensor data")
            previous = stop
        if end != len(data) - 8 - size:
            raise ValueError("Trailing/unreferenced tensor bytes (possible polyglot)")
        fp, _ = fingerprint_file(name, data)
        fingerprint = fp.to_dict() if fp else None
        if fingerprint:
            fingerprint.pop("file_path", None)
        return "safetensors", {
            "header_offset": 8,
            "header": header,
            "fingerprint": fingerprint,
        }
    if suffix == "gguf":
        if len(data) < 24 or data[:4] != b"GGUF":
            raise ValueError("GGUF magic/header mismatch")
        version, tensors, entries = struct.unpack_from("<IQQ", data, 4)
        if version not in (2, 3) or entries > MAX_ITEMS or tensors > MAX_ITEMS:
            raise ValueError("Unsupported GGUF version/count")
        # Reject nested/large arrays before the existing recursive metadata parser.
        pos, metadata = 24, {}
        for _ in range(entries):
            offset = pos
            key, pos = gguf_string(data, pos)
            kind = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if kind == 9:
                element, count = struct.unpack_from("<IQ", data, pos)
                if element == 9 or count > MAX_ITEMS:
                    raise ValueError("Nested/oversized GGUF arrays unsupported")
            value, pos = gguf_value(data, pos, kind)
            if key in metadata:
                raise ValueError("Duplicate GGUF metadata")
            metadata[key] = {"offset": offset, "value": value}
        tensor_info = []
        for _ in range(tensors):
            offset = pos
            key, pos = gguf_string(data, pos)
            dims = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if not 1 <= dims <= 4:
                raise ValueError("Oversized GGUF dimensions")
            shape = list(struct.unpack_from("<" + "Q" * dims, data, pos))
            pos += dims * 8
            kind, relative = struct.unpack_from("<IQ", data, pos)
            pos += 12
            if any(d > 2**31 for d in shape):
                raise ValueError("Oversized GGUF tensor")
            tensor_info.append(
                {
                    "name": key,
                    "shape": shape,
                    "type": kind,
                    "relative_offset": relative,
                    "descriptor_offset": offset,
                }
            )
        if pos > len(data) or (tensors == 0 and pos != len(data)):
            raise ValueError("Trailing/truncated GGUF bytes with no tensor payload")
        return "gguf", {
            "version": version,
            "metadata": metadata,
            "tensors": tensor_info,
            "parsed_header_end": pos,
            "limitation": "Tensor payload layout/quantization not validated",
        }
    if suffix in {"pkl", "pickle", "pt", "pth", "bin", "ckpt", "joblib"}:
        stream, ops = io.BytesIO(data), []
        for op, arg, pos in pickletools.genops(stream):
            if len(ops) >= MAX_ITEMS:
                raise ValueError("Pickle opcode count exceeds limit")
            ops.append(
                {
                    "opcode": op.name,
                    "offset": pos,
                    "argument": repr(arg)[:256],
                    "argument_sha256": digest(repr(arg).encode()),
                }
            )
        if stream.tell() != len(data) or not ops or ops[-1]["opcode"] != "STOP":
            raise ValueError("Trailing/truncated pickle (possible polyglot)")
        return "pickle", {"opcodes": ops, "limitation": "Opcode inspection, never deserialization"}
    if suffix == "py":
        text = data.decode("utf-8")
        if "\0" in text or data.startswith((b"GGUF", b"\x80")):
            raise ValueError("Source content/extension mismatch")
        tree = ast.parse(text)
        nodes = [
            {"type": type(n).__name__, "line": getattr(n, "lineno", None)} for n in ast.walk(tree)
        ]
        if len(nodes) > MAX_ITEMS:
            raise ValueError("Source AST exceeds limit")
        return "python-source", {"nodes": nodes, "source_sha256": digest(data)}
    raise ValueError("Unsupported extension; use .safetensors, .gguf, .pkl/.pt or .py")


def inspect(item: dict) -> dict:
    name = item["name"]
    data = base64.b64decode(item["data"], validate=True)
    result = {"name": name, "size": len(data), "sha256": digest(data), "status": "UNKNOWN"}
    if not data or len(data) > MAX_FILE:
        result["error"] = "Empty or oversized file"
        return result
    try:
        fmt, details = structure(name, data)
        findings = (
            analyze_source_file(name, data.decode("utf-8"), data)
            if fmt == "python-source"
            else analyze_binary_file(name, data)
        )
        result.update(
            format=fmt,
            structures=details,
            structure_sha256=digest(json.dumps(details, sort_keys=True, allow_nan=False).encode()),
            findings=[asdict(f) for f in findings],
            status="CONCERNS" if findings else "NO_PATTERN_FOUND",
        )
    except (
        ValueError,
        UnicodeError,
        struct.error,
        IndexError,
        TypeError,
        KeyError,
        RecursionError,
        SyntaxError,
        OverflowError,
    ) as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
    return result


def main():
    # Imports precede seal; bytes and JSON are parsed only after the syscall filter.
    containment = seal()
    request = json.loads(sys.stdin.buffer.read(12 * 1024**2))
    result = {"containment": containment, "files": [inspect(item) for item in request["files"]]}
    output = json.dumps(
        result,
        allow_nan=False,
        default=lambda value: value.value if isinstance(value, Enum) else str(value),
    )
    if len(output.encode()) > MAX_FILE:
        output = json.dumps({"status": "UNKNOWN", "error": "Output limit exceeded", "files": []})
    print(output)


if __name__ == "__main__":
    main()
