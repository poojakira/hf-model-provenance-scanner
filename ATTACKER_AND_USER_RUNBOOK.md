# Authorized local validation guide

This is defensive repository validation on controlled synthetic fixtures, not permission to target an external service or execute untrusted model code. The current independent security closure is BLOCKED; this guide does not restart or replace it.

Use the Linux inspector setup and complete commands in [TESTING.md](docs/TESTING.md). Its browser acceptance invokes actual static engines and worker boundaries. For focused development, existing `tests/test_workbench.py`, `tests/test_pickle_scanner.py`, `tests/test_gguf_scanner.py`, `tests/test_safetensors_scanner.py` and `tests/test_security_rejects.py` describe real assertions. Selected tests are not the full regression or proof of all formats/platforms.

Keep tests and artifacts scoped to the exact candidate SHA, environment, actual inputs/configuration and executed commands. Preserve failing/incomplete outcomes, separate skipped cases and native subtests, and inspect downloaded report checksums. Do not run a model, enable `--sandbox`, broaden syscall permissions or remove negative assertions to obtain a green result.

The old portable executor and kernel-profile examples have [separate limitations](scanner/isolation/README.md); they are not the local worker or an approved arbitrary-code sandbox. No live remote target, paid service, new provider key, security-policy change or credential validation is needed for the documented local workflow.
