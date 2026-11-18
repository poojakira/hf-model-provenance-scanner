# Archive packaging correction

Source remains 16ff6f87f2f8f2832624d736c57c16e8809c1e5b. The first non-release archive 7627ad9d9ffb46b0ce8992acc82becb052375da8 at tag evidence/local-workbench-20261116 omitted some already-generated files because repository Git ignore rules applied during staging. Public-byte verification caught this packaging defect; no complete-public-archive claim was accepted.

This complete follow-up archive explicitly includes every reviewed release-evidence file, including ignored logs/packages/coverage outputs. It preserves the first immutable tag and does not rewrite source or tags. Final test results are scoped to the same source, not to either evidence-only commit. The software readiness decision remains PARTIAL.
