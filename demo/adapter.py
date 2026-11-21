import base64
import json
import struct

from scanner.workbench.server import provenance, report, validate

SPEC = {
    "title": "AI Model Trust Inspector",
    "version": "0.3.0",
    "description": "Compare actual synthetic SafeTensors bytes through the existing "
    "bounded Linux static-inspection worker.",
    "scenarios": [
        {"id": "identical", "label": "Identical SafeTensors bytes under different filenames"},
        {"id": "changed", "label": "Same tensor shape · changed weight bytes"},
        {"id": "metadata", "label": "Same weight bytes · changed metadata"},
    ],
    "limitations": [
        "The notebook generates tiny synthetic SafeTensors fixtures; no arbitrary upload or model execution.",
        "The actual local sealed worker inspects bytes; failure or unavailable containment remains UNKNOWN.",
        "Fingerprints and static structures do not prove model safety, publisher identity or semantic equivalence.",
        "Full local inspector independent security closure remains BLOCKED; this demo does not close it.",
    ],
    "repository": "https://github.com/poojakira/hf-model-provenance-scanner/tree/codex/local-workbench-20261116",
}


def fixture(weight, label):
    header = json.dumps(
        {
            "__metadata__": {"fixture": label},
            "synthetic_weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        },
        separators=(",", ":"),
    ).encode()
    return struct.pack("<Q", len(header)) + header + struct.pack("<f", weight)


def run(scenario):
    if scenario not in {item["id"] for item in SPEC["scenarios"]}:
        raise ValueError("Choose one of the documented synthetic scenarios")
    left = fixture(1.0, "synthetic")
    right = fixture(
        2.0 if scenario == "changed" else 1.0, "changed" if scenario == "metadata" else "synthetic"
    )
    payload = {
        "files": [
            {"name": "artifact-a.safetensors", "data": base64.b64encode(left).decode()},
            {"name": "artifact-b.safetensors", "data": base64.b64encode(right).decode()},
        ]
    }
    validate(payload)
    result = report(payload, provenance())
    if result["assessment"] == "UNKNOWN":
        summary = "UNKNOWN — static worker did not complete; no successful analysis claimed"
    else:
        summary = (
            "Actual file bytes equal: "
            + str(result["comparison"]["bytes_equal"])
            + "; static structures equal: "
            + str(result["comparison"]["structures_equal"])
        )
    return {"summary": summary, "engine_report": result}
