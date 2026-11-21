# Operations and CLI runbook

## Choose the actual surface

| Surface | Entry point | Behavior and boundary |
|---|---|---|
| Linux local inspector | `python -m scanner.workbench.server` / `hf-inspector` | Loopback 8763; one/two bounded uploads, real static worker, compare/export; no remote requests |
| Static scanner CLI | `python -m scanner.cli` / `hf-scanner` | Local path or optional remote repository collection; different size/format/isolation contract |
| Authenticated remote admission | `uvicorn scanner.service:app` after service-extra installation | Repository-ID scans, API key/allowlist and shared process limits; not local upload |
| Historical dashboards | `make dashboard` | Serves static visualization assets on 8080; not actual uploaded-file inspection |

Use [README setup](README.md#start-locally) for the browser and [INSPECTOR.md](docs/INSPECTOR.md) for limits, data flow, health and shutdown. Runtime software is 0.3.0; local schema 1 and remote admission API 1.0.0 are separate contracts.

## Local CLI examples

Use the reviewed checkout's environment. These commands scan supplied bytes without model loading. Explicit `--mode local --no-network` avoids the default `both` mode's remote-repository interpretation. Configuration defaults to `.hf-scanner.toml` if that file exists; review it as trusted configuration. The Python 3.10 fallback supports only a limited simple-TOML subset; Python 3.11+ uses tomllib.

```sh
python -m scanner.cli --version
python -m scanner.cli --help
python -m scanner.cli ./authorized-model --mode local --no-network --format json --output report.json --fail-on high --enforce
python -m scanner.cli ./authorized-model --mode local --no-network --format sarif --output report.sarif --fail-on high --enforce
```

A target can be an existing local directory or file. The directory walker/source limit defaults to 512 KiB; binary analysis defaults to `--max-binary-mb 100`. These CLI bounds differ from the inspector's strict 4 MiB per file and syscall-contained worker. CLI analysis itself is not automatically placed in that worker. The --no-network flag forces local mode; it is not an OS egress filter for optional verifier executables or other integrations. It may read local signatures and invoke an installed cosign/gpg/minisign verifier with fixed argv; verifier presence does not supply a trusted publisher/key policy. Review authorized local targets and configuration before use.

`--format` accepts json, sarif, text or html. `--verbose` includes INFO findings; `--quiet` suppresses report output. `--output` writes to the operator-selected path. `--runtime-policy`, `--aibom` and `--save-baseline` also create output files; review paths and access. Reports can contain names, paths and evidence from supplied artifacts.

## Interpret completeness and exit status

| Observation | Meaning |
|---|---|
| `COMPLETE` | Scanner counted all selected in-scope files as inspected within its rules/limits; not proof of benign content or exhaustive semantic coverage |
| `PARTIAL` | Some input was skipped; preserve skip count/details and do not call it clean |
| `INDETERMINATE` | Error or unanalyzable stream prevented full inspection |
| `UNKNOWN` | Nothing inspected or coverage cannot be established |
| Exit 0 | No severity-threshold failure; with `--enforce`, completeness must also be COMPLETE. It never authorizes deployment by itself. |
| Exit 1 | Severity threshold exceeded, or enforce mode rejected incomplete/indeterminate/unknown coverage |
| Exit 2 | Runtime failure or argparse error; do not turn it into a clean result |
| Exit 3 | Certain invalid local targets rejected after parsing |

Review the report's `error`, `completeness`, skipped details, actual scope and configuration as well as exit code. The optional TOML scanner.fail_on value can override the command-line severity setting. Risk scores are internal rule aggregation, not calibrated compromise probabilities.

## Optional remote collection

```sh
python -m scanner.cli org/model --mode remote --revision REVIEWED_COMMIT --format json --output remote-report.json --fail-on high --enforce
```

This command is a template, not a remote scan executed in this documentation pass. Remote operation retrieves HF metadata/content, may require an approved HF token for gated/private repositories, resolves a revision to an immutable commit, and downloads only supported files within the network client's default 10 MiB cap. Review `artifact_revision`, skipped weights and completeness. Redirect/destination restrictions and token stripping do not establish publisher identity or model safety. Prefer runtime credential storage; passing a token as an argv value can expose it to process inspection. No provider key is needed for the local inspector.

## Baselines and other optional modes

`--save-baseline baseline.json` stores a local scan baseline; `--baseline baseline.json` compares later evidence. A changed hash or finding is not proof of a malicious rug-pull. Keep the baseline under operator-controlled provenance/access; do not replace it automatically after an alert. AIBOM generation records scan-derived inventory; it is not a signed certification. See [signing boundaries](docs/supply-chain/SIGNING.md).

`--sandbox` is disabled and returns an argument error before loading a target. Do not recommend it for untrusted execution. The separate [portable executor abstraction](scanner/isolation/README.md) and profile files do not establish the inspector's boundary or a general execution sandbox.

`--protect` creates the runtime monitor and watches the scanner's own process while alive; it does not automatically attach to every model process or launch a model. The parsed `--protect-daemon` flag has no implemented daemon branch. Runtime monitor source/egress/behavioral heuristics require their own integration and validation; they are not a host firewall or field prevention guarantee. No such monitor was activated by this documentation pass.

## Build, test and recovery

Use [TESTING.md](docs/TESTING.md) for pinned environments and complete verification. `make test` first installs a sibling attack-v19-core and downloads data; it is not the minimal offline inspector test command. `make format` mutates source, whereas `ruff format --check` validates it. Optional ATT&CK enrichment is separate from the local browser's core analyzers.

For an ambiguous finding or worker failure, preserve the exact source/clean state, configuration, hashes, timestamps and a minimal authorized synthetic reproducer. Never publish credentials or private model bytes merely to file an issue. [SECURITY.md](SECURITY.md) describes private reporting.

Stop only the owned service/process. To roll back, keep local edits/reports, use a previously reviewed checkout and a new separate virtual environment, run that source's checks, then restart its documented entry point. Do not rewrite shared history, delete an arbitrary installation directory or assume code rollback reverses external notifications/actions. The current `install.sh` installs the reviewed local checkout into a **new** venv and refuses an existing path; it does not fetch remote source or edit shell profiles. Linux helper and old Windows installer are distinct; the latter's current behavior is not validated here.

No production backup/recovery timing, uptime, load target or public deployment is established. The local inspector has no persistent backend data to restore; the optional CLI/service/integrations may have reports/baselines/runtime state that the operator must protect explicitly.
