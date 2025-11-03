## Secret Scanner (Cross-Platform)

A fast, cross-platform secret scanner for source code. It detects common credential patterns and high-entropy strings, respects .gitignore, and outputs either human-readable or JSON reports.

### Features
- Common secret regex signatures (AWS, GitHub, Google, Slack, private keys, etc.)
- High-entropy detector to catch unknown secrets
- Respects `.gitignore` (via `pathspec`)
- Skips binary/large files
- JSON output for CI pipelines
- Works on Windows, macOS, and Linux (Python 3.8+)

### Install

```bash
# Create virtual environment
python -m venv .venv

# Activate it
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Windows CMD: .venv\Scripts\activate.bat
# macOS/Linux: source .venv/bin/activate

# Install dependencies and the package
pip install -r requirements.txt
pip install -e .
```

### Usage

**Important:** Activate the virtual environment first:
```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Windows CMD
.venv\Scripts\activate.bat

# macOS/Linux
source .venv/bin/activate
```

Then run the scanner:
```bash
python -m secret_scanner scan .
```

Common options:

```bash
# JSON output (CI-friendly) and non-zero exit on findings
python -m secret_scanner scan . --json --fail-on-findings

# Tune entropy and file size
python -m secret_scanner scan . --entropy-threshold 4.5 --max-file-size 1048576

# Provide extra ignore patterns (in addition to .gitignore)
python -m secret_scanner scan . --exclude "**/dist/**" --exclude "**/*.min.js"

# Disable entropy if you only want signature matches
python -m secret_scanner scan . --no-entropy

# Save JSON results to a file
python -m secret_scanner scan . --json --output-file findings.json
```

### Exit Codes
- 0: No findings or findings allowed
- 1: Findings and `--fail-on-findings` set

### Notes
- The scanner ignores common binary and archive formats and files larger than the configured `--max-file-size`.
- `.gitignore` is honored if present at the scan root. You can also pass `--ignore-file` to add additional ignore rules.

### Development

```bash
python -m secret_scanner scan tests/fixtures --json | jq .
```



