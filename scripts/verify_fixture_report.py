from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_fixture_report.py REPORT")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    findings = report.get("results", [])
    if len(findings) != 1:
        raise SystemExit(f"expected 1 finding, found {len(findings)}")
    print("repository workflow report verified")


if __name__ == "__main__":
    main()
