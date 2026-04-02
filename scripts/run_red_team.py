#!/usr/bin/env python3
"""
Red team test runner.
Runs all 6 attack tests plus edge cases and live scenario, prints a narrative report.

Usage:
    python scripts/run_red_team.py
    python scripts/run_red_team.py --verbose
    python scripts/run_red_team.py --report-file results.txt
"""

import subprocess
import sys
from datetime import datetime, timezone

ATTACKS = [
    ("Attack 1: Result Fabrication",   "tests/red_team/test_attack_1_fabrication.py"),
    ("Attack 2: Log Tampering",        "tests/red_team/test_attack_2_log_tamper.py"),
    ("Attack 3: Fake Signature",       "tests/red_team/test_attack_3_fake_sig.py"),
    ("Attack 4: Rollback Denial",      "tests/red_team/test_attack_4_rollback_lie.py"),
    ("Attack 5: Replay Attack",        "tests/red_team/test_attack_5_replay.py"),
    ("Attack 6: Backdated Intent",     "tests/red_team/test_attack_6_backdate.py"),
    ("Edge Cases",                     "tests/red_team/test_edge_cases.py"),
    ("Live Scenario",                  "tests/red_team/test_live_scenario.py"),
]


def run(verbose: bool = False, report_file: str | None = None):
    lines = []

    def emit(line: str = ""):
        print(line)
        lines.append(line)

    emit("=" * 62)
    emit("ARC PROTOCOL  -  RED TEAM TEST RESULTS")
    emit(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    emit("=" * 62)

    results = []
    all_passed = True

    for name, path in ATTACKS:
        cmd = ["pytest", path, "--tb=short", "-q"]
        if verbose:
            cmd.append("-v")

        result = subprocess.run(cmd, capture_output=True, text=True)
        passed = result.returncode == 0
        results.append((name, passed, result.stdout, result.stderr))
        if not passed:
            all_passed = False

        status = "✓  PASSED" if passed else "✗  FAILED  -  hole detected or test error"
        emit(f"\n  {name}")
        emit(f"  {status}")

        if not passed:
            # Show last 800 chars of output for context
            output = (result.stdout + result.stderr).strip()
            if output:
                emit(f"\n  --- Failure output (last 800 chars) ---")
                emit(output[-800:])
                emit(f"  ---")

    emit("\n" + "=" * 62)
    if all_passed:
        emit("OVERALL: ALL ATTACKS CAUGHT ✓")
        emit("The protocol withstood all adversarial tests.")
    else:
        failed = [n for n, p, _, _ in results if not p]
        emit("OVERALL: FAILURES DETECTED ✗")
        emit(f"Failed test suites: {', '.join(failed)}")
        emit("")
        emit("NOTE: Some failures are EXPECTED  -  they expose documented holes.")
        emit("See RED_TEAM_FINDINGS.md for details on each hole.")
    emit("=" * 62)

    if report_file:
        with open(report_file, "w") as f:
            f.write("\n".join(lines))
        print(f"\nReport written to: {report_file}")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARC Red Team Test Runner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose pytest output")
    parser.add_argument("--report-file", help="Write report to this file path")
    args = parser.parse_args()

    run(verbose=args.verbose, report_file=args.report_file)
