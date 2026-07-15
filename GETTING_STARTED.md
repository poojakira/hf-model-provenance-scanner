# Getting Started Guide

A complete step-by-step guide for first-time users. No prior knowledge required.

---

## What Is This Tool?

This is a **security scanner** for AI/ML models downloaded from HuggingFace. Before you load or run any model from the internet, this tool checks it for hidden malware, credential stealers, and supply-chain attacks.

**Think of it like antivirus, but specifically for AI models.**

---

## Prerequisites

You need **Python 3.9 or newer** installed. That's it. No other software required.

### Check if Python is installed:

**Windows (open PowerShell or Command Prompt):**
```
py --version
```
or
```
python --version
```

**Linux / macOS (open Terminal):**
```
python3 --version
```

If you see `Python 3.9` or higher (3.10, 3.11, 3.12, etc.), you're good.

If Python is not installed:
- **Windows**: Download from https://python.org/downloads — check "Add to PATH" during install
- **macOS**: `brew install python3` or download from python.org
- **Linux (Ubuntu/Debian)**: `sudo apt install python3`
- **Linux (Fedora/RHEL)**: `sudo dnf install python3`

---

## Installation

### Option A: Clone and Run (Recommended for first time)

**Windows (PowerShell):**
```powershell
# Step 1: Open PowerShell (press Win+X, choose "PowerShell" or "Terminal")

# Step 2: Clone the scanner
git clone https://github.com/poojakira/hf-model-provenance-scanner.git

# Step 3: Go into the folder
cd hf-model-provenance-scanner

# Step 4: Verify it works
py -m scanner.cli --version
# Should print: hf-scanner 0.2.0
```

**Windows (Command Prompt / cmd.exe):**
```cmd
REM Step 1: Open cmd (press Win+R, type cmd, press Enter)

REM Step 2: Clone the scanner
git clone https://github.com/poojakira/hf-model-provenance-scanner.git

REM Step 3: Go into the folder
cd hf-model-provenance-scanner

REM Step 4: Verify it works
py -m scanner.cli --version
```

**Linux / macOS (Terminal):**
```bash
# Step 1: Open Terminal

# Step 2: Clone the scanner
git clone https://github.com/poojakira/hf-model-provenance-scanner.git

# Step 3: Go into the folder
cd hf-model-provenance-scanner

# Step 4: Verify it works
python3 -m scanner.cli --version
# Should print: hf-scanner 0.2.0
```

### Option B: Install with pip (adds `hf-scanner` command globally)

**Windows:**
```powershell
pip install -e .
hf-scanner --version
```

**Linux / macOS:**
```bash
pip install -e .
hf-scanner --version
```

After pip install, you can use `hf-scanner` from any directory instead of `python3 -m scanner.cli`.

---

## How to Scan a Model

### Scenario 1: Scan a model you already downloaded

You downloaded a model to a folder on your computer. Scan it before using it:

**Windows:**
```powershell
# If you cloned the scanner to C:\Users\you\hf-model-provenance-scanner:
cd C:\Users\you\hf-model-provenance-scanner

# Scan your downloaded model folder:
py -m scanner.cli "C:\Users\you\Downloads\my-model" --mode local --fail-on high
```

**Linux / macOS:**
```bash
cd ~/hf-model-provenance-scanner

# Scan your downloaded model folder:
python3 -m scanner.cli ~/Downloads/my-model --mode local --fail-on high
```

### Scenario 2: Scan a HuggingFace repo before downloading

You want to check if a model on HuggingFace is safe BEFORE downloading it:

**Windows:**
```powershell
py -m scanner.cli "meta-llama/Llama-3-8B" --mode remote --fail-on high
```

**Linux / macOS:**
```bash
python3 -m scanner.cli meta-llama/Llama-3-8B --mode remote --fail-on high
```

### Scenario 3: Quick check with maximum detection

Use `--sandbox` for instrumented runtime coverage of selected Python code paths. This is not an OS isolation boundary:

**Windows:**
```powershell
py -m scanner.cli "C:\path\to\model" --mode local --sandbox --fail-on high
```

**Linux / macOS:**
```bash
python3 -m scanner.cli ./path/to/model --mode local --sandbox --fail-on high
```

---

## Understanding the Output

### Clean model (safe to use):
```
Risk: LOW (0/100)

0 findings (0 critical, 0 high, 0 medium)
```
This means: **Safe.** No suspicious code found.

### Dangerous model (DO NOT USE):
```
Risk: CRITICAL (100/100)
  - 5 critical findings
  - 3 high findings

[CRITICAL] HFS-050 model.pkl:0 - Pickle file contains dangerous callable (os.system)
[CRITICAL] HFS-001 loader.py:12 - subprocess with powershell
[HIGH] HFS-014 loader.py:15 - Hidden window execution
```
This means: **MALWARE DETECTED.** Do not load this model. Delete it immediately.

### Exit codes (for CI/CD):
- `0` = Clean (or findings below your threshold)
- `1` = Findings at or above `--fail-on` severity — **blocked**
- `2` = Scanner error
- `3` = Invalid arguments

---

## Common Commands Reference

| What you want to do | Windows (PowerShell) | Linux / macOS |
|---------------------|---------------------|---------------|
| Check scanner version | `py -m scanner.cli --version` | `python3 -m scanner.cli --version` |
| See all options | `py -m scanner.cli --help` | `python3 -m scanner.cli --help` |
| Scan local folder | `py -m scanner.cli .\model --mode local` | `python3 -m scanner.cli ./model --mode local` |
| Scan HuggingFace repo | `py -m scanner.cli org/model --mode remote` | `python3 -m scanner.cli org/model --mode remote` |
| Block on critical only | `py -m scanner.cli .\model --fail-on critical` | `python3 -m scanner.cli ./model --fail-on critical` |
| Block on high or above | `py -m scanner.cli .\model --fail-on high` | `python3 -m scanner.cli ./model --fail-on high` |
| Never block (info only) | `py -m scanner.cli .\model --fail-on never` | `python3 -m scanner.cli ./model --fail-on never` |
| Maximum detection | `py -m scanner.cli .\model --sandbox` | `python3 -m scanner.cli ./model --sandbox` |
| JSON output | `py -m scanner.cli .\model --format json` | `python3 -m scanner.cli ./model --format json` |
| Save report to file | `py -m scanner.cli .\model --output report.txt` | `python3 -m scanner.cli ./model --output report.txt` |
| Show all findings (incl. info) | `py -m scanner.cli .\model --verbose` | `python3 -m scanner.cli ./model --verbose` |

---

## Try It Right Now (Test with included samples)

The scanner comes with sample malicious and safe files for testing:

**Windows:**
```powershell
cd hf-model-provenance-scanner

# Generate test files first:
py tests\generate_binary_fixtures.py

# Scan malicious samples (should find many issues):
py -m scanner.cli tests\fixtures\binary --mode local --fail-on never --verbose

# Scan safe sample (should find nothing):
py -m scanner.cli tests\fixtures\benign --mode local --fail-on never
```

**Linux / macOS:**
```bash
cd hf-model-provenance-scanner

# Generate test files first:
python3 tests/generate_binary_fixtures.py

# Scan malicious samples (should find many issues):
python3 -m scanner.cli tests/fixtures/binary --mode local --fail-on never --verbose

# Scan safe sample (should find nothing):
python3 -m scanner.cli tests/fixtures/benign --mode local --fail-on never
```

---

## Troubleshooting

### "python3 is not recognized" (Windows)
Use `py` instead of `python3`. The `py` launcher is Windows-specific.

### "py is not recognized" (Windows)
Python is not in your PATH. Reinstall Python from python.org and check "Add to PATH".

### "No module named scanner" 
Make sure you're inside the `hf-model-provenance-scanner` directory when running the command.

### "Permission denied" (Linux/macOS)
Use `pip install --user -e .` instead of `pip install -e .`

### Scanner seems slow with --sandbox
The instrumented runtime engine runs each Python file in a subprocess (default 30s timeout). For faster scans, omit `--sandbox` — the other 4 engines still catch most attacks.

---

## What Happens Behind the Scenes

When you run the scanner, it does this in order:

1. **Walks all files** in the target directory
2. **For each Python file**: runs 4 analysis engines (AST patterns, taint tracking, symbolic resolution, and optionally sandbox execution)
3. **For each binary model file** (.pkl, .pt, .safetensors, .gguf, .onnx, .h5): parses the binary format and checks for malicious content
4. **For config/shell files**: checks for suspicious URLs, commands, and patterns
5. **Computes a risk score** (0-100) based on all findings
6. **Reports results** in your chosen format

Total scan time for a typical model repo: **under 1 second** (without sandbox).

---

## Next Steps

- Read [INTEGRATION.md](INTEGRATION.md) to add scanning to your CI/CD pipeline
- Read [LIMITATIONS.md](LIMITATIONS.md) to understand what the scanner can and cannot do
- Open `dashboard/security/index.html` in a browser to see the visual dashboard
- Run `python3 tests/redteam/simulate_attacks.py` to see the scanner catch 12 real-world attacks live
