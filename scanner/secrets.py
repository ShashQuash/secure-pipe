import re
import math
from pathlib import Path

PATTERNS = [
    {
        "name": "Generic API Key",
        "regex": r'(?i)(api_key|apikey|api-key)\s*=\s*["\']([A-Za-z0-9/+]{20,})["\']',
        "severity": "HIGH"
    },
    {
        "name": "Generic Password",
        "regex": r'(?i)(password|passwd|pwd)\s*=\s*["\'](.{6,})["\']',
        "severity": "HIGH"
    },
    {
        "name": "AWS Access Key",
        "regex": r'AKIA[0-9A-Z]{16}',
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Token",
        "regex": r'ghp_[A-Za-z0-9]{36}',
        "severity": "CRITICAL"
    },
    {
        "name": "Generic Secret",
        "regex": r'(?i)(secret|token)\s*=\s*["\']([A-Za-z0-9/+]{20,})["\']',
        "severity": "MEDIUM"
    },
]
ALLOWLIST = [
    "your_api_key_here",
    "your_secret_here", 
    "example",
    "placeholder",
    "dummy",
    "test",
    "xxxx",
]

def calc_entropy(s: str) -> float:
    """
    Shannon entropy — measures randomness of a string.
    Higher score = more random = more likely a real secret.
    Real secrets typically score above 3.5.
    Placeholders like 'YOUR_KEY_HERE' score below 3.0.
    """
    if not s:
        return 0.0
    
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 2)

def scan_file(filepath: str) -> list[dict]:
    """
    Scans a single file for hardcoded secrets.
    Returns a list of findings, each with file, line, pattern name, severity.
    """
    findings = []
    path = Path(filepath)

    if not path.exists() or not path.is_file():
        return findings

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(f"[!] Could not read {filepath}: {e}")
        return findings

    for line_num, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            match = re.search(pattern["regex"], line)
            if not match:
                continue


            matched_value = match.group(0)

            if any(re.search(rf'\b{re.escape(allow)}\b', matched_value.lower()) for allow in ALLOWLIST):
                continue

            # Check entropy — skip low-randomness strings
            # We check the last captured group if it exists, else full match
            check_str = match.group(len(match.groups())) if match.groups() else matched_value
            entropy = calc_entropy(check_str)
            if entropy < 2.5:
                continue

            findings.append({
                "file": str(filepath),
                "line": line_num,
                "pattern": pattern["name"],
                "severity": pattern["severity"],
                "entropy": entropy,
                "matched_line": line.strip()
            })

    return findings