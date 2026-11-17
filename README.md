# AI Model Trust Inspector

Inspect and compare actual local model artifacts without loading a model. The browser calls this repository’s static Python, pickle opcode, SafeTensors and GGUF analyzers in a bounded Linux worker. This is the local workbench for `hf-scanner` 0.3.0.

**Status: PARTIAL.** The local workflow is implemented. Final commit-scoped results are generated outside source; independent review, all historical documentation claims, optional remote integrations, container deployment and production approval remain separate gates. No static result establishes behavioral safety or trustworthy model origin. Curated fixture detection is not a field accuracy measurement.

## Start locally

Requires Linux, Python 3.10+, `libseccomp.so.2`, and a current browser. No credentials or paid service is needed. From this reviewed checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-local.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m scanner.workbench.server
```

Open **http://127.0.0.1:8763**. Select one or two files and choose **Inspect files**. Change a file and inspect again. The **Try synthetic comparison** button analyzes clearly labeled synthetic Python source through the same worker. **Download report + manifest** exports findings, hashes, structures, limits, unknowns and source provenance. Stop with Ctrl+C.

Supported local inputs: `.safetensors`, `.gguf`, raw pickle (`.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.joblib`) and UTF-8 `.py`. Each file must contain 1 byte–4 MiB. ZIP-based PyTorch, archives, compressed files, ONNX and Keras are not supported by this workbench. Use a plain ASCII filename without directories.

## What the evidence means

- `CONCERNS`: the actual engine found configured static patterns. Review evidence and context.
- `NO_PATTERN_FOUND`: no configured pattern was found in the supported inspection scope. Safety and origin remain unknown.
- `UNKNOWN`: malformed, unsupported, failed, timed-out or incomplete inspection. Never a clean result.
- Comparison covers file hashes, metadata and parsed serialized structures. It does not establish semantic equivalence or model behavior.

Raw pickle opcodes include offsets; Python findings include source locations where available; SafeTensors exposes header/tensor descriptors and tensor byte hashes; GGUF exposes metadata/descriptor offsets. GGUF tensor payload layout and quantization are **NOT VERIFIED**. Static rules can miss threats and flag benign content.

The worker has a fail-closed Linux seccomp syscall allowlist, `no_new_privs`, CPU/address-space limits, bounded pipes and a wall-clock deadline. It cannot open filesystem paths, create sockets, execute programs or create children after initialization. This is not a VM/container or protection against kernel vulnerabilities. Inputs remain in bounded process memory; they are never extracted, imported, unpickled, written to disk or downloaded. Exports are saved only when you choose Download. Local processes and browser extensions are outside the user-isolation boundary.

![Actual desktop workbench; evidence archive publication follows independent review](https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/refs/tags/evidence/local-workbench-20261116/release-evidence/browser/desktop.png)

The screenshot belongs to an immutable evidence archive published after independent review. Before that publication, inspect the generated local browser artifact described in [evidence guidance](docs/EVIDENCE.md).

## Existing CLI and admission API

The local scanner CLI remains available with `.venv/bin/hf-scanner --help`. The existing remote admission service in `scanner/service.py` retains its API-key authorization and network policy. Its **1.0.0 API version** describes that separate service contract; the software/engine version is **0.3.0** and the local API schema version is **1**. The upload UI never calls the remote service and does not bypass its authentication. The old dashboards are explicitly synthetic, historical visualization assets.

## Engineering documentation

- [Product, architecture, threat model, API, operations and user/developer guide](docs/INSPECTOR.md)
- [Testing and adversarial checks](docs/TESTING.md)
- [Evidence and known limitations](docs/EVIDENCE.md)
- [Security reporting and autopsy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Read-only baseline and branch audit](docs/internal/REPOSITORY_AUDIT.md)

Older documents carry a historical-scope notice. Their metrics and production claims are not current release evidence.
