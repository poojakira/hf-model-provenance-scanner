# First local inspection

The [README](README.md#start-locally) is the canonical Linux/Python 3.10+ installation. Install its pinned packages in a new virtual environment and ensure `libseccomp.so.2` is available. Start `python -m scanner.workbench.server` with that environment; open the printed IPv4-loopback URL. No HF account, token, downloaded model or paid service is needed. Windows/macOS CLI support does not establish local Linux-worker support on those systems.

## Try the actual workflow

Choose **Try synthetic comparison**. This inspects two explicitly synthetic Python source files through the real bounded worker. Review the two file hashes, static findings, changed structures and limitations. The suspicious source is analyzed, not executed. A detected pattern is an investigation signal; no result certifies a model safe.

To inspect your own authorized artifact, choose Artifact A; optionally select B. Each file must be 1 byte–4 MiB, with an ASCII basename and supported extension. Choose **Inspect files**, expand evidence, replace a selection and rerun, then download the report/manifest. [Supported structures](docs/INSPECTOR.md#supported-formats-and-boundaries) are narrower than all formats understood by the separate CLI.

## Recover from an error

| Observation | Action |
|---|---|
| Cannot connect | Check the owning terminal and exact printed port. Use `--port 8765` for a port conflict; do not widen the bind. |
| Missing module/dependency | Activate the intended environment and install from the reviewed local checkout/lock. Avoid global or user-site installation to hide environment drift. |
| Worker unavailable/UNKNOWN | Check Linux/libseccomp prerequisites and the actual error. Restart if needed; never enable unrestricted fallback. |
| Filename/size/unsupported input | Select a supported bounded file with an ASCII basename. Renaming an archive does not make it supported. |
| 403 | Use the exact local origin; reload after server restart to obtain the new in-memory token. |
| 429 | Another inspection is active; retry after it completes. |
| Prior export disappeared | Selection changes/new scans invalidate old evidence. Inspect the current selection again. |

Ctrl-C stops the server; workers are disposable. There is no backend report database, extraction directory or input cleanup operation. Downloads remain wherever you saved them. Do not import private artifacts into a shared/untrusted desktop or publish unreviewed reports.

For the separate scanner CLI and optional remote admission service, use [RUNBOOK.md](RUNBOOK.md) and [API_VERSIONING.md](docs/API_VERSIONING.md). Legacy dashboard pages do not run this upload workflow. Quantified performance and detection claims require exact-source raw evidence; this guide supplies no startup-time or accuracy guarantee.
