import json
from datetime import datetime


# Severity ranking for sorting (higher = more urgent)
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def normalise_secrets(findings: list[dict]) -> list[dict]:
    """Convert Layer 1 (secrets) findings into the common schema."""
    normalised = []
    for f in findings:
        normalised.append({
            "layer": "SECRETS",
            "severity": f.get("severity", "MEDIUM"),
            "location": f"{f.get('file')}:{f.get('line')}",
            "title": f.get("pattern", "Hardcoded secret"),
            "detail": f.get("matched_line", "")
        })
    return normalised


def normalise_dependencies(findings: list[dict]) -> list[dict]:
    """Convert Layer 2 (SCA) findings into the common schema."""
    normalised = []
    for f in findings:
        fix = f.get("fix_version", ["No fix"])
        fix_str = ", ".join(fix) if isinstance(fix, list) else str(fix)
        normalised.append({
            "layer": "DEPENDENCY",
            "severity": f.get("severity", "HIGH"),
            "location": f"{f.get('package')}=={f.get('version')}",
            "title": f.get("cve_id", "Known vulnerability"),
            "detail": f"Fix: {fix_str} — {f.get('description', '')[:120]}"
        })
    return normalised


def normalise_sast(findings: list[dict]) -> list[dict]:
    """Convert Layer 3 (SAST) findings into the common schema."""
    normalised = []
    for f in findings:
        normalised.append({
            "layer": "SAST",
            "severity": f.get("severity", "MEDIUM"),
            "location": f"{f.get('file')}:{f.get('line')}",
            "title": f.get("issue", "Dangerous pattern"),
            "detail": ""
        })
    return normalised


def build_report(secrets, dependencies, sast) -> dict:
    """
    Combines all findings into one normalised, sorted report.
    """
    all_findings = (
        normalise_secrets(secrets)
        + normalise_dependencies(dependencies)
        + normalise_sast(sast)
    )

    # Sort by severity, most urgent first
    all_findings.sort(
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True
    )

    # Count by severity
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    return {
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings
    }


def print_report(report: dict):
    """Pretty terminal output."""
    print("\n" + "=" * 50)
    print("           SECUREPIPE SECURITY REPORT")
    print("=" * 50)
    print(f"Scan time: {report['scan_time']}")
    print(f"Total findings: {report['total_findings']}")
    print(f"  CRITICAL: {report['summary']['CRITICAL']}")
    print(f"  HIGH:     {report['summary']['HIGH']}")
    print(f"  MEDIUM:   {report['summary']['MEDIUM']}")
    print(f"  LOW:      {report['summary']['LOW']}")
    print("=" * 50)

    for f in report["findings"]:
        print(f"\n[{f['severity']}] ({f['layer']}) {f['title']}")
        print(f"  Location: {f['location']}")
        if f["detail"]:
            print(f"  Detail: {f['detail']}")


def save_json_report(report: dict, filepath: str = "securepipe_report.json"):
    """Save the report as JSON for CI/CD consumption."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] JSON report saved to {filepath}")