# Attacker and User Runbook

This file gives two safe execution paths: normal scanner usage and adversarial regression usage. Attacker commands are `[TEST-ONLY]`; they scan local fixtures and must not be used against systems you do not own or have permission to test.

## User Run

Install the scanner locally:

```powershell
py -3.12 -m pip install -e .
```

Scan the current repository as a local target without failing on intentionally committed security fixtures:

```powershell
py -3.12 -m scanner.cli . --mode local --fail-on never
```

Run the scanner unit tests:

```powershell
py -3.12 -m pytest tests/test_pickle_scanner.py -q
```

## Attacker Run [TEST-ONLY]

Run the renamed-pickle and pickle-analysis bypass regression suite:

```powershell
py -3.12 -m pytest tests/test_pickle_scanner.py -q
```

Run additional binary/model format security tests:

```powershell
py -3.12 -m pytest tests/test_gguf_scanner.py tests/test_safetensors_scanner.py tests/test_security_rejects.py -q
```

## Pass Condition

All selected tests exit `0`; renamed pickle payloads and Python source gadgets must be detected by content, not trusted by extension.

## Honest Limit

These commands prove local static-scanner regressions only. They do not prove full Hugging Face Hub-scale malware coverage, sandbox safety, or commercial supply-chain parity.
