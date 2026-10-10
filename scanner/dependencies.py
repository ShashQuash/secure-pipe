import subprocess
import json
import sys


def scan_dependencies(requirements_file: str = "requirements.txt") -> list[dict]:
    """
    Runs pip-audit against a requirements file.
    Returns a list of vulnerable packages with CVE details.
    """
    findings = []
    seen = set()  # (package, advisory id) pairs already reported

    try:
        # sys.executable = the exact Python running this script,
        # so pip-audit is found even when several Pythons are installed
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", requirements_file, "--format", "json"],
            capture_output=True,
            text=True
        )

        if not result.stdout.strip():
            print("[!] pip-audit returned no output.")
            if result.stderr.strip():
                print(f"[!] pip-audit error: {result.stderr.strip().splitlines()[-1]}")
            return findings

        data = json.loads(result.stdout)

        for dependency in data.get("dependencies", []):
            package = dependency.get("name", "unknown")
            version = dependency.get("version", "unknown")
            vulns = dependency.get("vulns", [])

            for vuln in vulns:
                vuln_id = vuln.get("id", "N/A")

                # The vulnerability database can return the same advisory
                # more than once, so skip any (package, id) already added
                if (package, vuln_id) in seen:
                    continue
                seen.add((package, vuln_id))

                findings.append({
                    "package": package,
                    "version": version,
                    "cve_id": vuln_id,
                    "description": vuln.get("description", "No description available."),
                    "fix_version": vuln.get("fix_versions", ["No fix available"]),
                    # pip-audit gives no severity score, so every finding is marked HIGH
                    "severity": "HIGH"
                })

    except FileNotFoundError:
        print("[!] pip-audit not found. Run: pip install pip-audit")
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse pip-audit output: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

    return findings