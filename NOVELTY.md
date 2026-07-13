# Novelty, Data & Production-Readiness — honest, skeptical assessment

## Genuinely useful here

- **Layered static + behavioral analysis for HF artifacts**, framed end-to-end
  (pickle opcode parsing → AST/taint → symbolic de-obfuscation → sandbox →
  binary format parsers) with a rug-pull temporal baseline. The multi-engine
  design (an attacker must beat all of them) is a reasonable architecture.
- **Provenance is now trust-anchored (HFS-041).** cosign verification no longer
  treats a bare `verify-blob` as "verified"; without a pinned key/identity it
  reports that trust could not be established. A missing verifier already
  surfaces as HFS-039 (not silent-clean).
- **Install integrity** now supports commit-hash pinning, GPG tag verification,
  cosign self-verification, and a signed-release workflow (SHA256SUMS + keyless
  cosign). pip/PyPI is the recommended path.

## Be skeptical about these claims

- **"25+ detection rules"** — the code actually defines **61** rules
  (`scanner/rules/definitions.py`). The number is fine; the point is that *rule
  count is not detection quality*. Many rules are heuristics (entropy,
  Levenshtein typosquat, download-velocity) that produce false positives and
  false negatives; none are validated against a labeled malware corpus here.
- **"30/30 attacks detected | 0 false positives"** — this is against the repo's
  own crafted fixtures, i.e. a test the tool was written to pass. It is **not**
  evidence against real-world malware or on real benign models. Treat it as a
  regression suite, not a benchmark.
- **IOC feed exists but the hash DB is sparse.** `scanner/analyzer/ioc_feed.py`
  is real: it ships a seed `iocs.json` (bad domains, dangerous packages,
  vulnerable versions), supports SHA-256 hash IOCs, and can merge a remote feed
  with caching. Good. The honest caveat: the bundled known-bad **hash** set is
  small, so hash-based detection only catches samples someone has already
  reported. Subscribe it to a real feed (picklescan / model-scan / HF scans)
  and record provenance per entry before claiming community-level coverage.

## Data required before honest production claims

| Need | Why | Source | Scale |
|------|-----|--------|-------|
| Known-malicious pickle corpus | pickle load = RCE; must detect known bad | picklescan reports, Protect AI model-scan, HF malware scans | 1k+ |
| Clean SafeTensors baseline | Measure real false-positive rate | gpt2, bert-base, llama, sd (actual files) | 500+ |
| Impersonation pairs | Validate Levenshtein/homoglyph org detection | HF top-1k orgs + generated lookalikes | 10k pairs |
| SBOM tamper corpus | Verify hash cross-checking | real models + single-byte tamper + rehash | 5k |
| Temporal rug-pull set | Validate baseline-drift detection | track 100 models × 60 days of hash deltas | 6k snapshots |

**Honest shipping recommendation:** ship as a **static analyzer + provenance
checker**, not a "malware scanner," until HFS-042 is backed by a real feed and a
false-positive rate is measured on clean canonical models.

## Known gaps

- No independent pentest; no fuzzing of the pickle/AST parser boundary.
- Heuristic thresholds (entropy 5.7, Levenshtein ≤2) are unvalidated on real
  distributions.
- The sandbox depends on a container runtime being present; absent it, dynamic
  analysis is skipped.
