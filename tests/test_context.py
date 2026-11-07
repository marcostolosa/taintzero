from pathlib import Path

from taintzero.context import code_context, redact_text
from taintzero.models import Finding, Position


def test_redacts_common_secret_assignment() -> None:
    assert redact_text('api_key = "super-secret-value"') == "api_key =<REDACTED>"


def test_context_rejects_path_outside_root(tmp_path: Path) -> None:
    finding = Finding(
        rule_id="x",
        path="../outside.py",
        start=Position(1, 1),
        end=Position(1, 2),
        message="x",
        severity="ERROR",
    )
    try:
        code_context(tmp_path, finding, 2)
    except ValueError as exc:
        assert "sai do projeto" in str(exc)
    else:
        raise AssertionError("path traversal deveria ser rejeitado")
