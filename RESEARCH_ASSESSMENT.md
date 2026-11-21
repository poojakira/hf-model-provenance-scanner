# Research assessment and evidence boundaries

The repository implements static source/artifact rules, format-specific helpers, provenance/baseline utilities, a separate authenticated remote-admission path, and a bounded Linux local inspector. The browser's actual supported inputs and trust limits are [documented separately](docs/INSPECTOR.md). Existence of optional code does not prove it is active, complete or independently verified in every interface.

The strongest supported statement is that authorized local bytes reach real static analyzers and yield scoped findings/structures/hashes/unknowns. That is not universal malware detection, authenticated publisher/lineage, semantic model safety, prevention of a historical incident or superiority to a third-party scanner.

The current quantitative source ledger is [VERIFIED_METRICS.md](VERIFIED_METRICS.md) and [EVIDENCE.md](docs/EVIDENCE.md). Historical260/241/195 test counts retain their own source/date/environment. Curated33/33 fixture matches and zero actionable findings on four curated benign samples are regressions, not population precision/recall. Do not combine test counts, subtests or separate environments into one invented run.

A credible wider evaluation would need a versioned representative corpus, predeclared counting rules, explicit exclusions, identical comparison conditions, actual raw outputs and source/dependency/environment hashes. Historical third-party incident descriptions and maintainer-recorded development chronology require original independent artifacts; this documentation pass does not revalidate them. Field adoption, latency/throughput/scale, customer impact and certification remain unverified.

Independent closing security review remains BLOCKED. A documentation audit and engineering regressions establish their named observations, not that separate review's result. Future research/deployment milestones must preserve those distinctions.
