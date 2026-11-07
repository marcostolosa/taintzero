from taintzero.models import parse_findings


def test_parse_semgrep_finding() -> None:
    report = {
        "results": [
            {
                "check_id": "demo.rule",
                "path": "app.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 12},
                "extra": {"message": "demo", "severity": "ERROR", "metadata": {"cwe": "78"}},
            }
        ]
    }
    finding = parse_findings(report)[0]
    assert finding.rule_id == "demo.rule"
    assert finding.start.line == 3
    assert finding.metadata["cwe"] == "78"
    assert len(finding.fingerprint) == 24
