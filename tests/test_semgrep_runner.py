import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from taintzero.semgrep_runner import SemgrepError, run_semgrep


def test_fails_when_semgrep_json_contains_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    process = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"results": [], "errors": [{"message": "missing plugin"}]}),
        stderr="",
    )
    monkeypatch.setattr("taintzero.semgrep_runner.subprocess.run", lambda *args, **kwargs: process)
    monkeypatch.setattr("taintzero.semgrep_runner.shutil.which", lambda _name: "semgrep")

    with pytest.raises(SemgrepError, match="missing plugin"):
        run_semgrep(Path("target"), Path("rules"))


def test_accepts_clean_semgrep_report(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = {"results": [], "errors": []}
    process = SimpleNamespace(returncode=0, stdout=json.dumps(expected), stderr="")
    monkeypatch.setattr("taintzero.semgrep_runner.subprocess.run", lambda *args, **kwargs: process)
    monkeypatch.setattr("taintzero.semgrep_runner.shutil.which", lambda _name: "semgrep")

    assert run_semgrep(Path("target"), Path("rules")) == expected
