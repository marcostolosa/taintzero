from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class SemgrepError(RuntimeError):
    pass


def run_semgrep(target: Path, rules: Path | str | Sequence[Path | str]) -> dict[str, Any]:
    sibling = Path(sys.executable).with_name("semgrep.exe" if os.name == "nt" else "semgrep")
    executable = str(sibling) if sibling.is_file() else shutil.which("semgrep")
    if executable is None:
        raise SemgrepError("Semgrep não está no PATH. Instale com: pipx install semgrep")

    configs = [rules] if isinstance(rules, (str, Path)) else list(rules)
    if not configs:
        raise SemgrepError("Nenhuma configuração de regras foi selecionada")
    command = [executable, "scan"]
    for config in configs:
        command.extend(["--config", str(config)])
    command.extend(["--json", "--quiet", str(target)])
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    if process.returncode not in (0, 1):
        detail = process.stderr.strip() or process.stdout.strip() or "erro desconhecido"
        raise SemgrepError(f"Semgrep falhou ({process.returncode}): {detail}")
    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepError("Semgrep não retornou JSON válido") from exc
    errors = report.get("errors", [])
    if errors:
        first = errors[0]
        detail = first.get("message") if isinstance(first, dict) else str(first)
        raise SemgrepError(f"Semgrep reportou {len(errors)} erro(s): {detail}")
    return report
