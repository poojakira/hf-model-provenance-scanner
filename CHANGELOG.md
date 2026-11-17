# Changelog

## 0.3.0 — local candidate (not a production release)

- Added a loopback-only AI Model Trust Inspector using actual static repository engines, one/two bounded local files, comparisons, evidence and report/manifest downloads.
- Added fail-closed Linux seccomp syscall containment, no_new_privs, resource/deadline/concurrency limits and bounded parent worker pipes. No uploaded source/model execution, deserialization, extraction or downloads.
- Added structural validation and explicit UNKNOWN for unsupported/malformed files; retained GGUF payload and provenance limitations.
- Fixed installer destructive-target handling, CRLF syntax and Python requirement; install from reviewed local source into a new environment.
- Prevent installed distributions from inheriting an unrelated parent Git commit; generated health evidence omits the temporary local CSRF nonce.
- Keep native subtest totals separate from individual test outcomes in generated verification reports.
- Kept existing remote admission authentication and its distinct API version unchanged. Dynamic sandbox convenience remains disabled.
- Replaced current README claims with scoped task documentation; marked historical documents as historical. Final commit-scoped checks are generated outside source, not copied from prior metrics.

Earlier history remains in Git. Historical documents and synthetic dashboards are not current release evidence. No release tag/default-branch change is created by this local candidate.
