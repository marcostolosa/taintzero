from __future__ import annotations

import os
import tempfile
from pathlib import Path


def semgrep_environment() -> dict[str, str]:
    """Return an isolated, CI-safe environment for Semgrep subprocesses."""
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    runtime_dir = Path(tempfile.gettempdir()) / "taintzero-semgrep"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    environment.setdefault("SEMGREP_SETTINGS_FILE", str(runtime_dir / "settings.yml"))
    environment.setdefault("SEMGREP_LOG_FILE", str(runtime_dir / "semgrep.log"))
    environment.setdefault("SEMGREP_VERSION_CACHE_PATH", str(runtime_dir / "version-cache"))
    return environment
