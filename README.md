# SecurePipe - Learning Project

A small security scanner for Python code that runs automatically on every push through GitHub Actions. It checks for hardcoded secrets, vulnerable dependencies and dangerous code patterns, puts everything into one report sorted by severity, and fails the build if it finds anything CRITICAL or HIGH.

I built it as a learning project to understand how security checks fit into a CI/CD pipeline, by writing a simple version of each check myself instead of only using ready-made tools.

## The red X on this repo is intentional

The latest workflow run on this repo fails, and it is supposed to.

The repo contains test files with planted problems (fake secrets, `eval()`, `os.system()`, outdated packages). SecurePipe finds them and exits with code 1, which tells GitHub Actions to block the build. If the run showed a green check, the scanner would be missing things.

The test files are:

| File | What it contains | Why |
|---|---|---|
| `scanner/test_dummy.py` | Fake API key, password and GitHub token, plus one placeholder and one `os.getenv()` call | Tests secrets detection, including two lines that should **not** be flagged |
| `scanner/test_sast.py` | `eval`, `exec`, `os.system`, `subprocess` with `shell=True`, `pickle.load` | Tests static analysis. The file is only parsed, never run |
| `requirement.txt` | `requests==2.18.0` and `flask==0.12.0` | Deliberately old versions with known vulnerabilities, for the dependency scan |

None of the secrets are real.

## How it works

```
push to main
    -> GitHub Actions starts a fresh Ubuntu runner
    -> installs Python and pip-audit
    -> runs main.py
         1. Secrets detection   (scanner/secrets.py)
         2. Dependency scan     (scanner/dependencies.py)
         3. Static analysis     (scanner/sast.py)
         4. Unified report      (reporter/report.py)
    -> exit 1 if any CRITICAL or HIGH finding -> build fails
       exit 0 otherwise                       -> build passes
```

**1. Secrets detection.** Regex patterns match the shape of common secrets (AWS keys, GitHub tokens, `password = "..."`, `api_key = "..."`). Two filters cut false positives: an allowlist skips obvious placeholders like `YOUR_API_KEY_HERE`, and a Shannon entropy check skips strings that are not random enough to be a real secret.

**2. Dependency scanning (SCA).** Runs `pip-audit` against a requirements file and lists every package version with a known vulnerability, the advisory ID and the version that fixes it. Duplicate advisories returned by the database are removed.

**3. Static analysis (SAST).** Uses Python's built-in `ast` module to parse code into a syntax tree and flag calls to `eval`, `exec`, `compile`, `os.system`, `pickle.load(s)`, `yaml.load` and `subprocess` with `shell=True`. Because it reads the syntax tree, the word "eval" inside a comment or string is not flagged, only real calls.

**4. Reporting.** The three scanners return findings in different shapes. The reporter converts them into one common format, sorts them by severity, prints a summary and saves `securepipe_report.json`.

**5. CI/CD gate.** `.github/workflows/securepipe.yml` runs the scan on every push and pull request to `main`. The exit code decides pass or fail.

## Sample output

```
==================================================
           SECUREPIPE SECURITY REPORT
==================================================
Total findings: 31
  CRITICAL: 3
  HIGH:     27
  MEDIUM:   1
  LOW:      0
==================================================

[CRITICAL] (SECRETS) GitHub Token
  Location: scanner/test_dummy.py:5

[CRITICAL] (SAST) Use of eval() — executes arbitrary code
  Location: scanner/test_sast.py:7

[HIGH] (DEPENDENCY) PYSEC-2018-28
  Location: requests==2.18.0
  Detail: Fix: 2.20.0 ...

[FAIL] Build blocked — 3 CRITICAL and 27 HIGH severity issues found.
```

The exact number of dependency findings changes over time as new vulnerabilities are published.

## Run it locally

```bash
git clone https://github.com/ShashQuash/secure-pipe.git
cd secure-pipe
python -m pip install pip-audit
python main.py
```

On Windows PowerShell, check the exit code with `echo $LASTEXITCODE` (it should print `1` with the test files in place).

## Limitations

This is a learning project, not a replacement for tools like Gitleaks, Bandit or Semgrep. Known gaps:

- **It scans fixed test files.** The paths are set in `main.py`. It does not yet walk through a whole repository.
- **Every dependency finding is marked HIGH.** pip-audit does not return a severity score, so there is no real CRITICAL/MEDIUM/LOW split for that layer.
- **Secrets detection is pattern-based.** A secret that does not match one of the patterns, or has low entropy, can be missed. The allowlist can also skip a real secret that happens to contain a word like "test".
- **The SAST rules are a short list.** It only catches direct `module.function()` calls, so `from os import system` followed by `system(...)` is missed.
- **The dependency scan needs internet access** to reach the vulnerability database.

## What I would add next

- Scan every `.py` file in a target folder instead of fixed paths
- Real severity for dependency findings using CVSS scores
- Docker image and a small web dashboard for the JSON report

## Tech

Python 3.12 · `ast` · `re` · pip-audit · GitHub Actions