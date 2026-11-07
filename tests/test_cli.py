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
