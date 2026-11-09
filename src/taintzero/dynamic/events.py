from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

EVENT_PREFIX = "TAINTZERO_EVENT "


@dataclass(frozen=True)
class DynamicEvent:
    event: str
    canary_id: str
    input_id: str
    symbol: str
    path: str | None = None
    line: int | None = None
    variants: tuple[str, ...] = ()
    blocked: bool = False
    schema_version: str = "1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> DynamicEvent:
        if not isinstance(value, dict):
            raise TypeError("evento dinâmico deve ser um objeto")
        required = ("event", "canary_id", "input_id", "symbol")
        if any(not isinstance(value.get(key), str) or not value[key] for key in required):
            raise ValueError("evento dinâmico contém campos obrigatórios inválidos")
        path = value.get("path")
        line = value.get("line")
        variants = value.get("variants", [])
        blocked = value.get("blocked", False)
        schema_version = value.get("schema_version", "1")
        if path is not None and not isinstance(path, str):
            raise ValueError("path do evento deve ser string ou null")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise ValueError("line do evento deve ser inteiro positivo ou null")
        if not isinstance(variants, (list, tuple)) or not all(
            isinstance(item, str) and item in {"raw", "url", "base64", "json"}
            for item in variants
        ):
            raise ValueError("variants do evento é inválido")
        if not isinstance(blocked, bool) or schema_version != "1":
            raise ValueError("versão ou política do evento é inválida")
        return cls(
            event=value["event"],
            canary_id=value["canary_id"],
            input_id=value["input_id"],
            symbol=value["symbol"],
            path=path,
            line=line,
            variants=tuple(variants),
            blocked=blocked,
            schema_version=schema_version,
        )


def parse_event_stream(text: str) -> tuple[tuple[DynamicEvent, ...], str]:
    """Extract protocol-prefixed JSONL events and preserve normal process output."""
    events: list[DynamicEvent] = []
    remaining: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if not stripped.startswith(EVENT_PREFIX):
            remaining.append(line)
            continue
        try:
            events.append(DynamicEvent.from_dict(json.loads(stripped[len(EVENT_PREFIX) :])))
        except (json.JSONDecodeError, TypeError, ValueError):
            # Untrusted target output cannot forge or break the harness report.
            remaining.append(line)
    return tuple(events), "".join(remaining)


def events_to_jsonl(events: tuple[DynamicEvent, ...]) -> str:
    return "".join(
        json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
        for event in events
    )
