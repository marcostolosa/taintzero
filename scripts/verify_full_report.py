from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_full_report.py REPORT")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    errors = report.get("errors")
    if errors:
        raise SystemExit(f"Semgrep reported {len(errors)} error(s)")
    findings = report.get("results")
    if not isinstance(findings, list) or not findings:
        raise SystemExit("expected at least one finding from the full ruleset")
    paths = {Path(item["path"]).name for item in findings}
    if "vulnerable.py" not in paths:
        raise SystemExit("full ruleset did not detect the vulnerable fixture")
    if "safe.py" in paths:
        raise SystemExit("full ruleset reported the safe fixture")
    print(f"full ruleset verified with {len(findings)} finding(s)")


if __name__ == "__main__":
    main()
