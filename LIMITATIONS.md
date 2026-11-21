# Capabilities and known limitations

**Release status: PARTIAL.** Software 0.3.0 supports actual local static inspection, not a certificate of safety or authenticated model provenance. [The inspector guide](docs/INSPECTOR.md) is the authoritative local-format/containment contract; the separate CLI has different formats, limits and optional network behavior.

| Area | Implemented scope | Unimplemented or unverified property |
|---|---|---|
| Local browser | One/two files, 1 byte–4 MiB each, findings/structures/hashes/comparison/export | Large production artifacts, public/multi-user hosting and persistent history |
| Formats | Raw pickle opcodes, SafeTensors supported descriptors/data hashes, GGUF metadata/descriptors, Python AST | ZIP/compressed/archive extraction; ONNX/Keras in the UI; full GGUF payload/quantization and newer unsupported dtypes |
| Static signals | Existing AST/pattern/taint-style/string rules and binary analyzers | Complete dynamic resolution, cross-file semantic proof, universal malware detection or backdoor absence |
| Comparison | Bytes, metadata and serialized structure evidence | Behavioral/semantic equivalence, publisher identity or training lineage |
| Local worker | Linux fail-closed seccomp allowlist, no_new_privs, CPU/address-space/time/pipe/concurrency bounds | VM/kernel-vulnerability protection, adversarial OS-user isolation, universal exhaustion protection |
| CLI | Static local/remote scan, completeness, reports, fingerprint/baseline/provenance utilities | Automatically using the local worker; complete artifact-format validation or trusted-signature policy |
| Remote admission | API-key/allowlist checks and per-process body/rate/concurrency/time controls | Tenant identities/policies, shared multi-worker quotas and hard termination of a timed-out scan thread |
| Output | Source/config/input hashes, evidence and report checksum | Signed attestation, externally anchored ledger, cryptographic memory erasure or automatically safe sharing |
| Runtime/executor | Optional monitor/executor code and illustrative profiles | An enabled `--sandbox`, implemented daemon-mode protection or verified arbitrary-code execution isolation |

`NO_PATTERN_FOUND`, CLI risk LOW and COMPLETE coverage do not mean safe. Unsupported, crashed, timed-out or incomplete inspector work is UNKNOWN. Static rules may miss attacks and flag benign content. The conservative workbench rejects legitimate files outside its bounded subset rather than silently widening execution authority.

## Evidence boundaries

The published implementation-source run at 16ff6f8 recorded 312 passing individual tests, 3 skips and 6 additional passing native subtests. Those counts belong to that source and are not later-head evidence. Independent current-source closing security review remains BLOCKED by the review service; engineering regressions do not supply an independent PASS. See [EVIDENCE.md](docs/EVIDENCE.md).

Historical 33/33 **curated** fixtures and zero actionable findings on four curated benign samples are repository regressions. They do not measure population recall/false-positive rate, compare third-party products or prove historical attacks would have been prevented. The old dynamic-execution tables/performance claims are not current capabilities. `--sandbox` remains disabled.

Independent closing review, broader representative datasets, exhaustive fuzz/mutation coverage, clean-machine/container runtime, complete historical external-fact verification and deployment-specific privacy/operations/recovery acceptance remain separate gates. No field accuracy, uptime, incident reduction, customer deployment or certification is asserted.
