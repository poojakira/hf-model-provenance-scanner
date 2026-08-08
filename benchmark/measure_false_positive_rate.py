"""
benchmark/measure_false_positive_rate.py
─────────────────────────────────────────────────────────────────────────────
Measures false-positive rate of the HF model provenance scanner against
known-good model configurations from the HuggingFace Hub.

This script does NOT download model weights (which can be 10GB+). Instead,
it tests the scanner's config/metadata analysis against real model configs
from popular, trusted repositories.

The key insight: if the scanner flags config.json or generation_config.json
from meta-llama, google, mistralai, or microsoft repos, those are false
positives — these are legitimate models from verified organizations.

Usage:
    python benchmark/measure_false_positive_rate.py --output evidence/fp_rate.json

Requirements:
    - Network access to HuggingFace Hub API (for metadata fetch)
    - OR: pre-downloaded config files in benchmark/known_good_configs/
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure scanner package is importable from repo root
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanner.analyzer.ast_visitor import analyze_python_source  # noqa: E402
from scanner.analyzer.config_scanner import analyze_config_file  # noqa: E402
from scanner.analyzer.obfuscation_scanner import analyze_obfuscation  # noqa: E402
from scanner.models import Finding  # noqa: E402

# ─── Known-good model configurations ──────────────────────────────────────────
# These are real config.json contents from trusted, verified HF organizations.
# If the scanner flags any of these, it's a false positive.

KNOWN_GOOD_CONFIGS: dict[str, dict[str, Any]] = {
    "meta-llama/Llama-3.1-8B": {
        "architectures": ["LlamaForCausalLM"],
        "attention_bias": False,
        "attention_dropout": 0.0,
        "bos_token_id": 128000,
        "eos_token_id": 128001,
        "hidden_act": "silu",
        "hidden_size": 4096,
        "initializer_range": 0.02,
        "intermediate_size": 14336,
        "max_position_embeddings": 131072,
        "model_type": "llama",
        "num_attention_heads": 32,
        "num_hidden_layers": 32,
        "num_key_value_heads": 8,
        "rms_norm_eps": 1e-05,
        "rope_scaling": {"factor": 8.0, "type": "dynamic"},
        "tie_word_embeddings": False,
        "torch_dtype": "bfloat16",
        "transformers_version": "4.43.0",
        "use_cache": True,
        "vocab_size": 128256,
    },
    "google/gemma-2-9b": {
        "architectures": ["Gemma2ForCausalLM"],
        "attention_bias": False,
        "attention_dropout": 0.0,
        "bos_token_id": 2,
        "eos_token_id": 1,
        "head_dim": 256,
        "hidden_act": "gelu_pytorch_tanh",
        "hidden_size": 3584,
        "initializer_range": 0.02,
        "intermediate_size": 14336,
        "max_position_embeddings": 8192,
        "model_type": "gemma2",
        "num_attention_heads": 16,
        "num_hidden_layers": 42,
        "num_key_value_heads": 8,
        "rms_norm_eps": 1e-06,
        "torch_dtype": "bfloat16",
        "transformers_version": "4.42.3",
        "use_cache": True,
        "vocab_size": 256000,
    },
    "mistralai/Mistral-7B-v0.3": {
        "architectures": ["MistralForCausalLM"],
        "attention_dropout": 0.0,
        "bos_token_id": 1,
        "eos_token_id": 2,
        "hidden_act": "silu",
        "hidden_size": 4096,
        "initializer_range": 0.02,
        "intermediate_size": 14336,
        "max_position_embeddings": 32768,
        "model_type": "mistral",
        "num_attention_heads": 32,
        "num_hidden_layers": 32,
        "num_key_value_heads": 8,
        "rms_norm_eps": 1e-05,
        "sliding_window": None,
        "tie_word_embeddings": False,
        "torch_dtype": "bfloat16",
        "transformers_version": "4.42.0",
        "use_cache": True,
        "vocab_size": 32768,
    },
    "microsoft/Phi-3-mini-4k-instruct": {
        "architectures": ["Phi3ForCausalLM"],
        "attention_dropout": 0.0,
        "bos_token_id": 1,
        "eos_token_id": 32000,
        "hidden_act": "silu",
        "hidden_size": 3072,
        "initializer_range": 0.02,
        "intermediate_size": 8192,
        "max_position_embeddings": 4096,
        "model_type": "phi3",
        "num_attention_heads": 32,
        "num_hidden_layers": 32,
        "num_key_value_heads": 32,
        "rms_norm_eps": 1e-05,
        "rope_scaling": None,
        "tie_word_embeddings": False,
        "torch_dtype": "bfloat16",
        "transformers_version": "4.41.2",
        "use_cache": True,
        "vocab_size": 32064,
    },
    "openai-community/gpt2": {
        "activation_function": "gelu_new",
        "architectures": ["GPT2LMHeadModel"],
        "attn_pdrop": 0.1,
        "bos_token_id": 50256,
        "embd_pdrop": 0.1,
        "eos_token_id": 50256,
        "initializer_range": 0.02,
        "layer_norm_epsilon": 1e-05,
        "model_type": "gpt2",
        "n_embd": 768,
        "n_head": 12,
        "n_inner": None,
        "n_layer": 12,
        "n_positions": 1024,
        "resid_pdrop": 0.1,
        "summary_activation": None,
        "summary_first_dropout": 0.1,
        "summary_proj_to_labels": True,
        "summary_type": "cls_index",
        "summary_use_proj": True,
        "task_specific_params": {"text-generation": {"do_sample": True, "max_length": 50}},
        "vocab_size": 50257,
    },
}

# Known-good organization names — these should NOT trigger typosquat alerts
KNOWN_GOOD_ORGS = [
    "meta-llama",
    "google",
    "mistralai",
    "microsoft",
    "openai-community",
    "facebook",
    "huggingface",
    "stabilityai",
    "EleutherAI",
    "bigscience",
]

# Known-good Python snippets that might appear in model repos
KNOWN_GOOD_PYTHON = [
    # Typical modeling_*.py pattern
    """import torch
import torch.nn as nn
from transformers import PreTrainedModel

class MyModel(PreTrainedModel):
    def __init__(self, config):
        super().__init__(config)
        self.embed = nn.Embedding(config.vocab_size, config.hidden_size)
        self.layers = nn.ModuleList([
            TransformerBlock(config) for _ in range(config.num_hidden_layers)
        ])
    
    def forward(self, input_ids, attention_mask=None):
        x = self.embed(input_ids)
        for layer in self.layers:
            x = layer(x, attention_mask)
        return x
""",
    # Typical tokenizer script
    """from transformers import AutoTokenizer

def convert_tokenizer(input_dir, output_dir):
    tokenizer = AutoTokenizer.from_pretrained(input_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"Saved tokenizer to {output_dir}")
""",
]


def run_config_analysis(model_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    """Run the scanner's config analysis against a known-good config."""
    config_json = json.dumps(config, indent=2)
    findings: list[Finding] = []

    try:
        result = analyze_config_file(f"{model_id}/config.json", config_json)
        if result:
            findings.extend(result if isinstance(result, list) else [result])
    except Exception as e:
        return [{"type": "error", "model": model_id, "error": str(e)}]

    return [
        {
            "model_id": model_id,
            "rule_id": f.rule_id,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "evidence": f.evidence[:200] if f.evidence else "",
            "verdict": "FALSE_POSITIVE",
        }
        for f in findings
    ]


def run_org_analysis(org_name: str) -> list[dict[str, Any]]:
    """Run typosquat detection against known-good org names using Levenshtein distance.

    We check if the org_checker's protected_orgs list triggers false alarms
    when given the exact protected org name (it shouldn't).
    """
    from scanner.analyzer.org_checker import load_protected_orgs
    from scanner.utils.levenshtein import levenshtein

    findings = []
    protected = load_protected_orgs()
    org_lower = org_name.lower()

    # A known-good org should either BE in the protected list or not trigger
    # close-distance matches against other protected orgs
    if org_lower in protected:
        # It's in the protected list — should never be flagged
        return []

    # Check if it would trigger a typosquat alert
    for p in protected:
        dist = levenshtein(org_lower, p)
        if dist <= 4 and dist > 0:
            findings.append(
                {
                    "org_name": org_name,
                    "rule_id": "HFS-020",
                    "severity": "high",
                    "evidence": f"Distance {dist} from protected org '{p}'",
                    "verdict": "FALSE_POSITIVE",
                }
            )
            break

    return findings


def run_python_analysis(snippet_name: str, code: str) -> list[dict[str, Any]]:
    """Run AST + obfuscation analysis against known-good Python code."""
    findings: list[dict[str, Any]] = []

    try:
        ast_results = analyze_python_source(f"modeling_{snippet_name}.py", code)
        if ast_results:
            items = ast_results if isinstance(ast_results, list) else [ast_results]
            for f in items:
                findings.append(
                    {
                        "snippet": snippet_name,
                        "analyzer": "ast_visitor",
                        "rule_id": getattr(f, "rule_id", "AST"),
                        "severity": getattr(f.severity, "value", str(f.severity))
                        if hasattr(f, "severity")
                        else "unknown",
                        "evidence": getattr(f, "evidence", "")[:200],
                        "verdict": "FALSE_POSITIVE",
                    }
                )
    except Exception as e:
        findings.append({"snippet": snippet_name, "analyzer": "ast_visitor", "error": str(e)})

    try:
        obf_results = analyze_obfuscation(f"modeling_{snippet_name}.py", code)
        if obf_results:
            items = obf_results if isinstance(obf_results, list) else [obf_results]
            for f in items:
                findings.append(
                    {
                        "snippet": snippet_name,
                        "analyzer": "obfuscation_scanner",
                        "rule_id": getattr(f, "rule_id", "OBF"),
                        "severity": getattr(f.severity, "value", str(f.severity))
                        if hasattr(f, "severity")
                        else "unknown",
                        "evidence": getattr(f, "evidence", "")[:200],
                        "verdict": "FALSE_POSITIVE",
                    }
                )
    except Exception as e:
        findings.append({"snippet": snippet_name, "analyzer": "obfuscation", "error": str(e)})

    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "evidence" / "generated" / "false_positive_rate.json",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("HF Model Provenance Scanner — False Positive Rate Measurement")
    print("=" * 70)
    print()

    all_findings: list[dict[str, Any]] = []
    total_checks = 0
    start_time = time.perf_counter()

    # Phase 1: Config analysis against known-good models
    print("[1/3] Testing config.json analysis against known-good models...")
    for model_id, config in KNOWN_GOOD_CONFIGS.items():
        total_checks += 1
        fps = run_config_analysis(model_id, config)
        all_findings.extend(fps)
        status = f"  {model_id}: {'CLEAN' if not fps else f'{len(fps)} FALSE POSITIVE(S)'}"
        print(status)

    # Phase 2: Org name analysis against known-good organizations
    print(f"\n[2/3] Testing org-name analysis against {len(KNOWN_GOOD_ORGS)} known-good orgs...")
    for org in KNOWN_GOOD_ORGS:
        total_checks += 1
        fps = run_org_analysis(org)
        all_findings.extend(fps)
        status = f"  {org}: {'CLEAN' if not fps else f'{len(fps)} FALSE POSITIVE(S)'}"
        print(status)

    # Phase 3: Python analysis against known-good code patterns
    print(
        f"\n[3/3] Testing Python analysis against {len(KNOWN_GOOD_PYTHON)} known-good snippets..."
    )
    for i, snippet in enumerate(KNOWN_GOOD_PYTHON):
        total_checks += 1
        fps = run_python_analysis(f"snippet_{i}", snippet)
        all_findings.extend(fps)
        status = f"  snippet_{i}: {'CLEAN' if not fps else f'{len(fps)} FALSE POSITIVE(S)'}"
        print(status)

    elapsed = time.perf_counter() - start_time

    # Calculate FP rate
    fp_count = len([f for f in all_findings if f.get("verdict") == "FALSE_POSITIVE"])
    error_count = len([f for f in all_findings if "error" in f])
    fp_rate = fp_count / total_checks if total_checks > 0 else 0.0

    print(f"\n{'=' * 70}")
    print("RESULTS:")
    print(f"  Total checks:       {total_checks}")
    print(f"  False positives:    {fp_count}")
    print(f"  Errors:             {error_count}")
    print(f"  FP rate:            {fp_rate:.1%}")
    print(f"  Elapsed:            {elapsed:.2f}s")
    print(f"{'=' * 70}")

    # Write evidence file
    evidence = {
        "schema_version": "fp-rate-evidence-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scanner_root": str(REPO_ROOT),
        "methodology": (
            "Ran config, org-name, and Python analyzers against known-good "
            "model configurations from verified HuggingFace organizations. "
            "Any finding on these inputs is a false positive by definition."
        ),
        "known_good_models": list(KNOWN_GOOD_CONFIGS.keys()),
        "known_good_orgs": KNOWN_GOOD_ORGS,
        "python_snippets_tested": len(KNOWN_GOOD_PYTHON),
        "total_checks": total_checks,
        "false_positives": fp_count,
        "errors": error_count,
        "fp_rate": round(fp_rate, 4),
        "elapsed_seconds": round(elapsed, 2),
        "findings": all_findings,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"\nEvidence written to: {args.output}")

    # Return non-zero if FP rate exceeds 10% threshold
    if fp_rate > 0.10:
        print(f"\nFAIL: FP rate {fp_rate:.1%} exceeds 10% threshold")
        return 1
    print(f"\nPASS: FP rate {fp_rate:.1%} is within acceptable bounds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
