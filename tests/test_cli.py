from __future__ import annotations

import io
import time
from pathlib import Path

from rich.console import Console

from taintzero import cli


def test_scan_progress_is_cp1252_safe(monkeypatch) -> None:
    output = io.BytesIO()
    stream = io.TextIOWrapper(output, encoding="cp1252", errors="strict")
    test_console = Console(file=stream, force_terminal=True, color_system=None)
    monkeypatch.setattr(cli, "console", test_console)

    def fake_scan(_target: Path, _configs: list[str | Path]) -> dict[str, list[object]]:
        time.sleep(0.1)
        return {"results": []}

    monkeypatch.setattr(cli, "run_semgrep", fake_scan)

    assert cli._scan_with_progress(Path("target"), [Path("rules")]) == {"results": []}
    stream.flush()
    assert "Semgrep conclu" in output.getvalue().decode("cp1252")


def test_parser_accepts_interprocedural_taint_command() -> None:
    args = cli._parser().parse_args(
        [
            "taint",
            "project",
            "--models",
            "models.yml",
            "--output",
            "report.json",
        ]
    )

    assert args.command == "taint"
    assert args.target == Path("project")
    assert args.output == Path("report.json")
    assert args.models == [Path("models.yml")]


def test_analyze_repo_uses_native_engine_by_default() -> None:
    args = cli._parser().parse_args(["analyze-repo", "project"])

    assert args.with_semgrep is False
    assert args.rules_profile is None


def test_explicit_rules_enable_semgrep_configuration() -> None:
    args = cli._parser().parse_args(
        ["analyze-repo", "project", "--rules-profile", "semgrep-all"]
    )

    assert args.rules_profile == "semgrep-all"
