from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib.parse import quote
from uuid import uuid4


@dataclass(frozen=True)
class Canary:
    id: str
    input_id: str
    marker: str

    @property
    def variants(self) -> dict[str, str]:
        raw = self.marker
        return {
            "raw": raw,
            "url": quote(raw, safe=""),
            "base64": base64.b64encode(raw.encode()).decode(),
            "json": json.dumps(raw, ensure_ascii=True)[1:-1],
        }


def create_canary(input_id: str) -> Canary:
    identifier = uuid4().hex
    return Canary(id=identifier, input_id=input_id, marker=f"TZCANARY_{identifier}")


def detect_canary(value: object, canary: Canary) -> tuple[str, ...]:
    if isinstance(value, bytes):
        rendered = value.decode("utf-8", errors="replace")
    else:
        rendered = str(value)
    return tuple(name for name, variant in canary.variants.items() if variant in rendered)
