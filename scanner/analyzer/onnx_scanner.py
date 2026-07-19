"""
ONNX Model Scanner — Detect custom operator abuse and graph manipulation.

ONNX models can contain:
1. Custom operators that load native code (DLLs/shared libraries)
2. External data references (URLs to untrusted endpoints)
3. Oversized initializer tensors (hiding payloads in model weights)
4. Graph manipulation (nodes that don't contribute to inference)
5. Metadata fields with injected content

ONNX uses protobuf serialization. We parse the minimal structures
needed without importing the onnx package (zero dependencies).
"""

import re

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Protobuf wire types
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_32BIT = 5

# ONNX protobuf field numbers we care about
# ModelProto fields:
#   1: ir_version (int64)
#   7: graph (GraphProto)
#   8: opset_import (repeated OperatorSetIdProto)
#   14: metadata_props (repeated StringStringEntryProto)
#   4: model_version (int64)
#   2: doc_string (string)
# GraphProto fields:
#   1: node (repeated NodeProto)
#   5: initializer (repeated TensorProto)
#   2: name (string)
# NodeProto fields:
#   1: input (repeated string)
#   2: output (repeated string)
#   3: name (string)
#   4: op_type (string)
#   5: domain (string)

# Known dangerous custom op domains
SUSPICIOUS_DOMAINS = {
    "", "custom", "com.microsoft", "ai.onnx.ml",
}

# Standard ONNX ops that are always safe
STANDARD_OPS = {
    "Abs", "Acos", "Acosh", "Add", "And", "ArgMax", "ArgMin",
    "Asin", "Asinh", "Atan", "Atanh", "AveragePool",
    "BatchNormalization", "BitShift",
    "Cast", "Ceil", "Clip", "Compress", "Concat", "ConcatFromSequence",
    "Constant", "ConstantOfShape", "Conv", "ConvInteger", "ConvTranspose",
    "Cos", "Cosh", "CumSum",
    "DepthToSpace", "Det", "Div", "Dropout", "DynamicQuantizeLinear",
    "Einsum", "Elu", "Equal", "Erf", "Exp", "Expand",
    "Flatten", "Floor", "GRU", "Gather", "GatherElements", "GatherND",
    "Gemm", "GlobalAveragePool", "GlobalLpPool", "GlobalMaxPool", "Greater",
    "HardSigmoid", "Hardmax", "Identity", "If",
    "InstanceNormalization", "IsInf", "IsNaN",
    "LRN", "LSTM", "LeakyRelu", "Less", "Log", "LogSoftmax", "Loop",
    "MatMul", "MatMulInteger", "Max", "MaxPool", "MaxUnpool", "Mean",
    "Min", "Mod", "Mul", "Multinomial",
    "Neg", "NonMaxSuppression", "NonZero", "Not",
    "OneHot", "Or", "PRelu", "Pad", "Pow",
    "QLinearConv", "QLinearMatMul", "QuantizeLinear",
    "RNN", "RandomNormal", "RandomNormalLike", "RandomUniform",
    "RandomUniformLike", "Reciprocal", "ReduceL1", "ReduceL2",
    "ReduceLogSum", "ReduceLogSumExp", "ReduceMax", "ReduceMean",
    "ReduceMin", "ReduceProd", "ReduceSum", "ReduceSumSquare",
    "Relu", "Reshape", "Resize", "ReverseSequence", "RoiAlign", "Round",
    "Scan", "Scatter", "ScatterElements", "ScatterND", "Selu",
    "Shape", "Shrink", "Sigmoid", "Sign", "Sin", "Sinh", "Size",
    "Slice", "Softmax", "Softplus", "Softsign", "SpaceToDepth",
    "Split", "Sqrt", "Squeeze", "Sub", "Sum",
    "Tan", "Tanh", "Tile", "TopK", "Transpose",
    "Unique", "Unsqueeze", "Where", "Xor",
    # Common additional ops
    "LayerNormalization", "GroupNormalization", "Attention",
    "BiasGelu", "FastGelu", "SkipLayerNormalization",
}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"powershell|cmd\.exe|/bin/(?:ba)?sh", re.IGNORECASE),
    re.compile(r"eval\s*\(|exec\s*\(|__import__", re.IGNORECASE),
    re.compile(r"base64|subprocess|os\.system", re.IGNORECASE),
]



def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id, severity=rule.severity, file_path=file_path,
        line_number=0, column=0, message=rule.description,
        evidence=evidence[:300], remediation=rule.remediation, cwe=rule.cwe,
    )


def is_onnx_file(file_path: str) -> bool:
    return file_path.lower().endswith(".onnx")


def analyze_onnx_file(file_path: str, data: bytes) -> list[Finding]:
    """Parse ONNX protobuf and scan for security issues."""
    findings: list[Finding] = []
    if len(data) < 10:
        findings.append(_make_finding("HFS-075", file_path, "File too small for ONNX"))
        return findings

    # Extract all readable strings from the protobuf
    strings_found: list[str] = []
    custom_ops: list[str] = []

    # Simple string extraction from protobuf binary
    i = 0
    while i < len(data) - 4:
        # Look for length-delimited fields (wire type 2)
        if i + 1 < len(data):
            tag_byte = data[i]
            wire_type = tag_byte & 0x07
            if wire_type == 2 and i + 2 < len(data):
                length = data[i + 1]
                if 4 < length < 200 and i + 2 + length <= len(data):
                    try:
                        s = data[i + 2:i + 2 + length].decode("utf-8")
                        if s.isprintable() and len(s) > 3:
                            strings_found.append(s)
                            # Check if it looks like an op name
                            if s[0].isupper() and s.isalnum():
                                custom_ops.append(s)
                    except UnicodeDecodeError:
                        pass
        i += 1

    # Check for custom operators
    for op in set(custom_ops):
        if op not in STANDARD_OPS and len(op) > 3:
            findings.append(_make_finding(
                "HFS-073", file_path,
                f"Non-standard ONNX operator: '{op}'"
            ))

    # Check strings for suspicious content
    for s in strings_found:
        url_match = URL_PATTERN.search(s)
        if url_match:
            findings.append(_make_finding(
                "HFS-074", file_path, f"URL in ONNX: {url_match.group()[:100]}"
            ))
        for pattern in SUSPICIOUS_STRING_PATTERNS:
            if pattern.search(s):
                findings.append(_make_finding(
                    "HFS-074", file_path, f"Suspicious string: '{s[:100]}'"
                ))
                break

    return findings
