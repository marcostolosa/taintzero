from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

LOCAL_PROVIDERS = {"ollama", "lm_studio", "vllm", "llamafile", "docker_model_runner"}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_base: str | None = None
    api_key_env: str | None = None
    temperature: float = 0.0
    max_tokens: int = 1800

    @property
    def model_id(self) -> str:
        prefix = f"{self.provider}/"
        return self.model if self.model.startswith(prefix) else f"{prefix}{self.model}"

    @property
    def is_local(self) -> bool:
        return self.provider in LOCAL_PROVIDERS


@dataclass(frozen=True)
class AnalysisConfig:
    context_lines: int = 20
    max_findings: int = 50
    redact_secrets: bool = True


@dataclass(frozen=True)
class AppConfig:
    llm: LLMConfig
    analysis: AnalysisConfig


def load_config(path: Path) -> AppConfig:
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    llm = raw.get("llm") or {}
    analysis = raw.get("analysis") or {}
    if not llm.get("provider") or not llm.get("model"):
        raise ValueError("A configuração exige llm.provider e llm.model")
    return AppConfig(
        llm=LLMConfig(
            provider=str(llm["provider"]),
            model=str(llm["model"]),
            api_base=llm.get("api_base"),
            api_key_env=llm.get("api_key_env"),
            temperature=float(llm.get("temperature", 0)),
            max_tokens=int(llm.get("max_tokens", 1800)),
        ),
        analysis=AnalysisConfig(
            context_lines=int(analysis.get("context_lines", 20)),
            max_findings=int(analysis.get("max_findings", 50)),
            redact_secrets=bool(analysis.get("redact_secrets", True)),
        ),
    )
