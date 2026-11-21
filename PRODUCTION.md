# Release and deployment governance

**Decision: PARTIAL. No production deployment is approved.** A workflow named Production Gate, an API version or an image build does not supply operational acceptance.

Promotion requires a frozen source and fresh regression/browser/static/security/build/documentation evidence identifying its exact SHA, clean state, commands, UTC intervals, environment/dependencies, skips, coverage settings and artifact hashes. Preserve the 75% coverage gate and all negative/recovery assertions. Distinguish Docker build from product-container runtime and generated SBOM from verified signing/attestation.

The local inspector is a trusted single-operator Linux application. Do not publicly proxy it, disable its origin/session/size/quota controls or replace fail-closed containment with unrestricted parsing. Remote admission and webhook services have separate credential, allowlist, timeout and authorization contracts; a keyless local UI does not authorize weakening those services. Per-process limits are not coordinated multi-worker quotas; remote timeout retains capacity until the worker completes and does not kill a thread.

Release blockers include independent security closure, missing publisher/lineage/behavior verification, complete format/large-file support, broader adversarial/benign evaluation and environment-specific security/privacy/load/backup/recovery review. Signing, registry publication, external notifications and cloud deployment need their own explicit authorization and actual evidence. No automatic release on arbitrary tag push is claimed; inspect the current workflow's manual publish inputs and existing-version-tag conditions.

The owner-selected remote branch set is `main` and `codex/local-workbench-20261116`. Additional dependency and unique-work branches were retired only after exact-tip annotated recovery tags and verified private backups; unreviewed changes were not merged. See [selected branches and recovery](docs/BRANCHES.md). Earlier branch counts/dispositions remain historical. Security automation and protected-main checks remain enabled.

[Evidence status](docs/EVIDENCE.md), [testing](docs/TESTING.md), [operations](RUNBOOK.md) and [security reporting](SECURITY.md) define the current boundaries. No default merge, package/container publication, external account activation or public service was created by this documentation update.
