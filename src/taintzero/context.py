from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s]+)"),
    re.compile(r"\b(?:sk|ghp|glpat)-[A-Za-z0-9_-]{16,}\b"),
]


def code_context(root: Path, finding: Finding, context_lines: int, redact: bool = True) -> str:
    target = (root / finding.path).resolve()
    root = root.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Caminho do achado sai do projeto: {finding.path}") from exc
    if not target.is_file():
        return "<arquivo indisponível>"

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    first = max(1, finding.start.line - context_lines)
    last = min(len(lines), finding.end.line + context_lines)
    rendered = "\n".join(f"{number:>5} | {lines[number - 1]}" for number in range(first, last + 1))
    return redact_text(rendered) if redact else rendered


def redact_text(value: str) -> str:
    for pattern in SECRET_PATTERNS:
        value = pattern.sub(lambda match: _redact_match(match.group(0)), value)
    return value


def _redact_match(value: str) -> str:
    if "=" in value:
        return value.split("=", 1)[0] + "=<REDACTED>"
    if ":" in value:
        return value.split(":", 1)[0] + ": <REDACTED>"
    return "<REDACTED>"
