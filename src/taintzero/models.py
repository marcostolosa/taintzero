from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class Position:
    line: int
    col: int

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Position:
        return cls(line=int(value.get("line", 1)), col=int(value.get("col", 1)))


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    start: Position
    end: Position
    message: str
    severity: str
    metadata: dict[str, Any] = field(default_factory=dict)
    dataflow_trace: dict[str, Any] | None = None
    fingerprint: str = ""

    @classmethod
    def from_semgrep(cls, value: dict[str, Any]) -> Finding:
        extra = value.get("extra") or {}
        fingerprint = extra.get("fingerprint") or _fingerprint(value)
        return cls(
            rule_id=str(value.get("check_id", "unknown")),
            path=str(value.get("path", "")),
            start=Position.from_dict(value.get("start") or {}),
            end=Position.from_dict(value.get("end") or {}),
            message=str(extra.get("message", "")),
            severity=str(extra.get("severity", "UNKNOWN")),
            metadata=dict(extra.get("metadata") or {}),
            dataflow_trace=extra.get("dataflow_trace"),
            fingerprint=str(fingerprint),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_findings(report: dict[str, Any]) -> list[Finding]:
    return [Finding.from_semgrep(item) for item in report.get("results", [])]


def _fingerprint(value: dict[str, Any]) -> str:
    start = value.get("start") or {}
    raw = ":".join(
        [
            str(value.get("check_id", "")),
            str(value.get("path", "")),
            str(start.get("line", "")),
            str(start.get("col", "")),
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()[:24]
