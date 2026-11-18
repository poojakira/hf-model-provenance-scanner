# Optional integration contracts

The [local inspector](README.md) requires no integration, keys or external service. CLI/admission/webhook/signing/monitoring examples are distinct paths. No CI installation in another repository, model download, external notification, registry publication or deployment was executed by this documentation pass.

## Integrate a local CLI result

Run a reviewed distribution in an isolated environment and use an explicit local target, `--no-network`, `--enforce` and a chosen severity threshold. Preserve JSON/SARIF and capture exit code without converting failures to success. The calling pipeline must stop its own model-loading/deployment step. Exit 0 and COMPLETE do not prove safety; review errors, skipped input, scope and findings.

```sh
python -m scanner.cli ./authorized-model --mode local --no-network --format json --output report.json --fail-on high --enforce
```

The JSON formatter is this scanner's native report, **not** GitLab's SAST report schema. SARIF output is a separate format. Uploading either to a service needs its permissions and schema validation; no generic cloud-platform adapter is implied. Pin reviewed package/source and action/image revisions in an actual integration rather than copying a moving branch or arbitrary old installer hash.

The checked-in `.pre-commit-hooks.yaml` invokes the CLI on `.` in local mode, suppresses output and disables filename passing. This is a configured repository scan, not automatic inspection of every file format or a completed integration test. Review thresholds/configuration, report visibility and scope before activation. `pre-commit install` is not required for the browser.

## Remote admission service

`scanner/service.py` exposes an authenticated repository-ID scan API. See [API_VERSIONING.md](docs/API_VERSIONING.md#remote-admission-api-100) for request/response/errors and credential/allowlist limits. Deployments need separately reviewed ingress/TLS, runtime credentials, shared quotas, storage/log policy and recovery. The local upload UI does not call or bypass this service.

## Webhook adapter and manual workflow

`integrations/huggingface_webhook.py` is a Python adapter/standalone HTTP helper, not a provider-neutral serverless deployment. Its request wrapper requires a 32+ character WEBHOOK_SECRET, checks the signed body within a 10 MiB cap and passes a verified event to the handler. Its signature convention is `X-Webhook-Secret: sha256=<HMAC-SHA256(body)>`; validate compatibility with the actual provider/gateway, not its name. Valid model events must supply a repository name and immutable `headSha`; otherwise they are ignored/rejected. The scanner uses remote enforce mode and an immutable revision. A returned admitted flag is a static-policy result, not a model-safety guarantee.

Optional NOTIFY_URL delivery sends finding summaries to a configured HTTPS destination subject to host/public-address checks and a short no-redirect request. NOTIFY_ALLOWED_HOSTS further scopes destinations. DNS/ingress/delivery reliability, receiver payload format and privacy require deployment review; a generic text payload does not prove compatibility with every Slack/Teams/Discord endpoint. Source code does not implement automatic HF discussion posting here. Do not activate notifications or share account/model context without specific destination/data authorization.

`.github/workflows/hf-webhook-scan.yml` currently has **workflow_dispatch only**; it does not declare repository_dispatch or an automatic HF webhook trigger. It needs a supplied repo_id and may use configured HF_TOKEN/Slack secrets. It exports parsed finding counts and has separate failure/notification logic; its scan command does not add `--enforce`. Review completeness/error handling before calling it an admission gate. A helper for HF discussion posting elsewhere does not establish that this workflow invokes it.

## Baselines, runtime and deployment examples

CLI baseline save/compare can flag changed hashes/content; it does not identify a malicious rug-pull by itself. Preserve the approved baseline and input revision privately. The runtime monitor/protect flags have their [actual limited scope](RUNBOOK.md#baselines-and-other-optional-modes); there is no verified host-wide daemon or automatic external process protection.

Use the Dockerfile only from a reviewed checkout and capture image digest, build/runtime behavior and isolation/network/filesystem policy. A mutable `docker build` from an internet Git branch is not reproducible evidence. Signing/attestation requires [separate checks](docs/supply-chain/SIGNING.md). Existing deployments, throughput, cost, platform partnerships and sub-two-minute activation are not established by source templates.

Rollback and credential rotation remain operator procedures. Avoid piping network scripts into a shell; current `install.sh` installs the reviewed **local** checkout into a new environment and refuses existing targets. An older downloaded script or Windows helper is not the current local-install contract.
