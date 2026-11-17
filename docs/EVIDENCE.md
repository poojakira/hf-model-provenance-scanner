# Evidence and limitations

Candidate status is **PARTIAL** until the entire master contract and independent review are satisfied. Fresh results are generated after freezing source, outside the checkout at `/workspace/work/evidence/hf-model-provenance-scanner/final` in the execution workspace. The source commit cannot contain a hash of itself. The generated manifest records actual SHA/clean state before and after checks, branch, UTC, environment/dependency locks, exact commands/results and artifact SHA-256 values. Future hosted CI generates its own evidence for the actual checked-out PR head. Local checks do not claim hosted CI success.

The README screenshot references `evidence/local-workbench-20261116`, an immutable non-release archive published only after independent review. Before publication, the local browser evidence is authoritative. No production release or default-branch integration is implied.

## Implemented scope

Local browser + actual static engines; inspect one/two bounded files; compare hashes/metadata/structures; source/object/offset evidence where available; report + manifest download; loopback/session/origin controls; fresh fail-closed syscall-contained child; bounded memory/time/pipes/connection concurrency; explicit UNKNOWN failures. See tests for executable assertions and final generated results for what actually passed.

## Not implemented / not verified

- Model execution, behavioral equivalence, backdoor absence and semantic accuracy: not established by static inspection.
- Trusted publisher signatures, training lineage, external provenance and model identity beyond provided bytes: UNKNOWN in this UI. Existing CLI utilities do not make uploads trusted.
- Large production artifacts, ZIP checkpoint extraction, compressed archives, ONNX/Keras UI and newer unsupported dtypes: not supported by the local workbench.
- Complete GGUF tensor payload layout/quantization validation: NOT VERIFIED; existing metadata rule array scanning is capped at 100 elements.
- Cross-account/tenant isolation, internet hosting, deployment-specific operational/privacy signoff, kernel security and VM isolation: not implemented/verified.
- Exhaustive fuzz/mutation testing, all historical branch claims/docs facts, live remote integrations, hosted CodeQL/Trivy and container deployment: do not infer verification from local acceptance.
- Branch protection visibility was blocked in baseline; refs with open dependency PRs remain held. Candidate engineering does not delete/push refs. Independent root review controls publication/branch cleanup.

## Documentation audit boundary

Current task-oriented docs are README, INSPECTOR, TESTING, EVIDENCE, SECURITY and CHANGELOG. Older documents/posters/evidence are preserved with a historical-scope notice. Their old counts, dates, claims and screenshots are not a current validation source. A generated tracked-file inventory parses source/config/scripts and checks local links; it does not establish every historical statement’s truth. Full historical semantic/documentation audit remains PARTIAL. No 33/33 curated fixture result is advertised as field accuracy.
