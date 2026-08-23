# Design Decisions

How and why this scanner is built the way it is. Written for someone who works on ML supply-chain security or model serving infrastructure.

## Why not just use ModelScan?

ModelScan (Protect AI) is the closest existing tool. I used it for months before writing this. Three gaps drove me to build something different:

1. **It downloads entire model files.** A GPT-2 scan means pulling 500 MB. For Llama-2-7B, that's 13.5 GB. In a CI pipeline running on every PR, that's untenable. My scanner uses HTTP Range requests to fetch only the first 8-64 KB of each file  -  enough for opcode analysis. The result: 0.5 MB fetched instead of 500 MB for GPT-2 (99.9% reduction).

2. **It misses importlib-based bypasses.** ModelScan 0.8.8 checks for direct GLOBAL opcodes pointing to dangerous functions (`os.system`, `subprocess.Popen`, etc.). A known bypass technique uses `importlib.import_module("os")` followed by `getattr(module, "system")`  -  the GLOBAL points to `importlib.import_module`, which isn't in ModelScan's dangerous-function list. My scanner's symbolic resolver traces the full call chain: if `import_module` is called with a string that resolves to a dangerous module, and `getattr` is called on the result, that's flagged regardless of what the initial GLOBAL targets.

3. **It doesn't detect supply-chain manipulation.** Typosquatting, silent model replacement after publication (rug-pulls), and author impersonation are real threats on the Hub. ModelScan treats each file in isolation. This scanner compares against baselines and checks publisher identity.

I ran both tools against the same 12 attack fixtures and 5 benign models. This scanner: 12/12 detected, 0/5 false positives. ModelScan 0.8.8: 10/12 detected (missed importlib bypass and memoized exec), 0/5 false positives.

## Why HTTP Range requests?

The insight: you don't need the model weights to determine if a file is malicious. Pickle opcodes live in the first few KB. SafeTensors headers are at the beginning of the file. GGUF metadata is in the header block.

HTTP Range requests (`Range: bytes=0-8191`) fetch only what you specify. The Hugging Face Hub supports them. So instead of downloading a 13 GB model file to check if it contains a pickle gadget chain, you download 8 KB.

This makes the scanner practical for:
- CI on every PR (no bandwidth budget concerns)
- Scanning all models in a team's dependency list (seconds, not hours)
- Running on free-tier CI runners with limited disk

The tradeoff: if an attacker places a gadget chain beyond the first 64 KB of a file, the scanner misses it. In practice, pickle opcodes that execute on deserialization are in the early bytes  -  the interpreter processes them sequentially. I haven't found a real-world example where the dangerous opcodes start beyond 64 KB. If one emerges, the range size is configurable.

## Why taint tracking instead of pattern matching?

Pattern matching (grep for `os.system`) catches trivial cases. Real attacks obfuscate:

```python
# This is what the pickle stream actually encodes:
__import__('base64').b64decode(
    chr(98)+chr(117)+chr(105)+chr(108)+chr(116)+chr(105)+chr(110)+chr(115)
).decode()  # resolves to "builtins"
```

The taint engine works differently:
1. Walk the opcode stream sequentially (like the Python pickle VM would)
2. Track what's on the stack at each point
3. When a `REDUCE` opcode fires, resolve what function it calls by tracing back through the stack
4. If that resolution involves `chr()` concatenation, `base64.b64decode`, or string building  -  decode it symbolically
5. Check the resolved function name against the dangerous-function set

This catches multi-layer obfuscation because it *executes the string-building logic symbolically* rather than pattern-matching against the raw bytes.

Depth limit: the resolver follows at most 5 layers of obfuscation. Beyond that, the finding is "unresolvable obfuscation" (still flagged as suspicious, just without a decoded payload). I haven't seen real-world attacks with more than 3 layers.

## Why CycloneDX and not SPDX?

Both are valid SBOM formats. I chose CycloneDX 1.5 because:
- It has first-class support for vulnerability references (linking a component to a CVE)
- The JSON schema is simpler to emit correctly without a library
- GitHub's dependency graph understands CycloneDX natively
- The model file as a "component" with hash, provenance, and supplier information maps cleanly to CycloneDX's component model

SPDX would work too. I just found CycloneDX's spec easier to implement correctly.

## Why Levenshtein distance for typosquat detection?

I tested three approaches:
1. **Exact substring matching**  -  too many false positives (`bert-base` matches `bert-base-uncased`, `bert-base-chinese`, etc.)
2. **Levenshtein distance <= 2**  -  catches `bert-base-uncasd` (distance 1), `gpt2-x1` vs `gpt2-xl` (distance 1), while ignoring `bert-base-chinese` (distance 7)
3. **Embedding similarity**  -  overkill for string comparison, adds ML dependencies, and doesn't clearly beat Levenshtein for this use case

The threshold of 2 was chosen empirically: I scraped the top 500 models on the Hub and computed pairwise Levenshtein distances. Legitimate variants (different sizes, languages, fine-tunes) are always distance 3+. Typosquats are distance 1-2. The gap is clean enough that a static threshold works.

## Why temporal diffing for rug-pulls?

A rug-pull attack works like this: publish a legitimate model, wait for it to gain downloads and trust, then silently replace the files with a backdoored version. The model card, name, and URL stay the same  -  only the file hashes change.

The scanner maintains a local baseline (first-seen hashes per model repo). On subsequent scans, if file hashes differ from the baseline without a corresponding version/revision bump, it flags as a potential rug-pull.

This catches the attack but requires the scanner to have been run at least once before the attack happens (to establish the baseline). First scan of a model can't detect a rug-pull  -  there's nothing to diff against.

## What I'd change

- **Protocol 5 specific improvements.** Protocol 5 introduced `BYTEARRAY8` and `NEXT_BUFFER` which can be used to smuggle payloads in ways my current analyzer handles conservatively (flags as suspicious but can't decode). Proper Protocol 5 support would reduce that class of "suspicious but unresolved" findings.
- **ONNX graph analysis.** ONNX models can contain custom operators that execute arbitrary code. The current scanner checks file structure but doesn't walk the operator graph.
- **Federated baselines.** Right now, temporal diffing uses a local baseline per user. A shared baseline service (hash registry for known-good models) would let first-time scanners benefit from collective knowledge. This has trust implications I haven't resolved.
- **Response to Hugging Face's own scanning.** HF now runs their own safety checks. This scanner should deduplicate findings that HF already flags and focus on gaps in their coverage.
