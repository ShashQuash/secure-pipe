import sys
from scanner.secrets import scan_file
from scanner.dependencies import scan_dependencies
from scanner.sast import scan_sast
from reporter.report import build_report, print_report, save_json_report


def main():
    # Run all three scanners
    secrets = scan_file("scanner/test_dummy.py")
    dependencies = scan_dependencies("requirement.txt")
    sast = scan_sast("scanner/test_sast.py")

    # Build unified report
    report = build_report(secrets, dependencies, sast)

    # Output
    print_report(report)
    save_json_report(report)

    # CI/CD gate — fail the build if serious issues found
    critical = report["summary"]["CRITICAL"]
    high = report["summary"]["HIGH"]

    if critical > 0 or high > 0:
        print(f"\n[FAIL] Build blocked — {critical} CRITICAL and {high} HIGH severity issues found.")
        sys.exit(1)
    else:
        print("\n[PASS] No critical or high severity issues found.")
        sys.exit(0)


if __name__ == "__main__":
    main()