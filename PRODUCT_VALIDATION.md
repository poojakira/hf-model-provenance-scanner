# Product Validation

## Product boundary
Non-executing inspection of model repositories and artifacts before they enter a trusted ML workflow.

## Real-world validation ladder
1. **Committed adversarial/benign fixtures** — deterministic regression evidence.
2. **Public-repository canary** — resolve a public Hugging Face repository to an immutable commit, scan only within configured safety limits, and record completeness plus skipped files.
3. **Format corpus** — pickle-derived, SafeTensors, GGUF, ONNX, Keras, source/config/dependency paths.
4. **CI admission contract** — incomplete scans fail when `--enforce` is used; JSON/SARIF remain machine-readable.
5. **External pilot** — a real model publisher or ML platform team evaluates findings on its own repositories.

## Evidence rules
A public-repository canary validates interoperability and failure behavior, not malware-detection efficacy. Fixture pass rates remain fixture-scoped.
