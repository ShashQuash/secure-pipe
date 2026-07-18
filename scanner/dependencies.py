import subprocess
import json


def scan_dependencies(requirements_file: str = "requirements.txt") -> list[dict]:
    """
    Runs pip-audit against a requirements file.
    Returns a list of vulnerable packages with CVE details.
    """
    findings = []

    try:
        result = subprocess.run(
            ["python", "-m", "pip_audit", "-r", requirements_file, "--format", "json"],
            capture_output=True,
            text=True
)
        if not result.stdout.strip():
            print("[!] pip-audit returned no output.")
            return findings
        
        if not result.stdout.strip():
            print("[!] pip-audit returned no output.")
            return findings
        
        data = json.loads(result.stdout)

        for dependency in data.get("dependencies", []):
            package = dependency.get("name", "unknown")
            version = dependency.get("version", "unknown")
            vulns = dependency.get("vulns", [])

            for vuln in vulns:
                findings.append({
                    "package": package,
                    "version": version,
                    "cve_id": vuln.get("id", "N/A"),
                    "description": vuln.get("description", "No description available."),
                    "fix_version": vuln.get("fix_versions", ["No fix available"]),
                    "severity": "HIGH"
                })

    except FileNotFoundError:
        print("[!] pip-audit not found. Run: pip install pip-audit")
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse pip-audit output: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

    return findings