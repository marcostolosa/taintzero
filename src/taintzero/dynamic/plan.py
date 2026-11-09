from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class DynamicInput:
    id: str
    environment: str


@dataclass(frozen=True)
class ExecutionPlan:
    image: str
    command: tuple[str, ...]
    inputs: tuple[DynamicInput, ...]
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpus: float = 1.0
    pids_limit: int = 128
    instrumentation: str = "python"
    sink_policy: str = "block"


def load_execution_plan(path: Path) -> ExecutionPlan:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PlanError(f"não foi possível carregar o plano {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise PlanError("plano dinâmico deve ser um objeto YAML")
    if str(document.get("version", "1")) != "1":
        raise PlanError("versão de plano dinâmico não suportada")
    image = document.get("image")
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*", image):
        raise PlanError("image inválida")
    command = document.get("command")
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item and "\x00" not in item for item in command
    ):
        raise PlanError("command deve ser uma lista não vazia de strings")
    raw_inputs = document.get("inputs") or []
    if not isinstance(raw_inputs, list):
        raise PlanError("inputs deve ser uma lista")
    inputs = tuple(_parse_input(entry, index) for index, entry in enumerate(raw_inputs, start=1))
    if len({item.id for item in inputs}) != len(inputs):
        raise PlanError("inputs contém ids duplicados")
    if len({item.environment for item in inputs}) != len(inputs):
        raise PlanError("inputs contém variáveis de ambiente duplicadas")
    return ExecutionPlan(
        image=image,
        command=tuple(command),
        inputs=inputs,
        timeout_seconds=_bounded_int(document, "timeout_seconds", 60, 1, 3600),
        memory_mb=_bounded_int(document, "memory_mb", 512, 64, 32768),
        cpus=_bounded_float(document, "cpus", 1.0, 0.1, 32.0),
        pids_limit=_bounded_int(document, "pids_limit", 128, 16, 4096),
        instrumentation=_choice(document, "instrumentation", "python", {"python", "none"}),
        sink_policy=_choice(document, "sink_policy", "block", {"block", "observe"}),
    )


def _parse_input(entry: Any, index: int) -> DynamicInput:
    if not isinstance(entry, dict):
        raise PlanError(f"inputs[{index}] deve ser um objeto")
    input_id = entry.get("id")
    environment = entry.get("environment")
    if not isinstance(input_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", input_id):
        raise PlanError(f"id inválido em inputs[{index}]")
    if not isinstance(environment, str) or not re.fullmatch(
        r"TAINTZERO_CANARY_[A-Z0-9_]+", environment
    ):
        raise PlanError(
            f"environment em inputs[{index}] deve começar com TAINTZERO_CANARY_"
        )
    return DynamicInput(id=input_id, environment=environment)


def _bounded_int(
    document: dict[str, Any], key: str, default: int, minimum: int, maximum: int
) -> int:
    value = document.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise PlanError(f"{key} deve estar entre {minimum} e {maximum}")
    return value


def _bounded_float(
    document: dict[str, Any], key: str, default: float, minimum: float, maximum: float
) -> float:
    value = document.get(key, default)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PlanError(f"{key} deve ser numérico")
    result = float(value)
    if not minimum <= result <= maximum:
        raise PlanError(f"{key} deve estar entre {minimum} e {maximum}")
    return result


def _choice(document: dict[str, Any], key: str, default: str, choices: set[str]) -> str:
    value = document.get(key, default)
    if not isinstance(value, str) or value not in choices:
        raise PlanError(f"{key} deve ser um de: {', '.join(sorted(choices))}")
    return value
