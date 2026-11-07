from __future__ import annotations

import json
import os
import re
from typing import Any

from .config import LLMConfig


class LLMError(RuntimeError):
    pass


def complete_json(config: LLMConfig, system: str, user: str) -> dict[str, Any]:
    try:
        from litellm import completion
    except ImportError as exc:
        raise LLMError("LiteLLM Core não está instalado") from exc

    api_key = None
    if config.api_key_env:
        api_key = os.environ.get(config.api_key_env)
        if not api_key:
            raise LLMError(f"Variável de ambiente ausente: {config.api_key_env}")

    kwargs: dict[str, Any] = {
        "model": config.model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if config.api_base:
        kwargs["api_base"] = config.api_base

    try:
        response = completion(**kwargs)
        content = response.choices[0].message.content
        return _parse_json(content or "")
    except LLMError:
        raise
    except Exception as exc:
        raise LLMError(f"Falha no provedor {config.provider}: {exc}") from exc


def _parse_json(value: str) -> dict[str, Any]:
    value = value.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", value, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        value = fenced.group(1)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise LLMError("O modelo não retornou JSON válido") from exc
    if not isinstance(parsed, dict):
        raise LLMError("O modelo deve retornar um objeto JSON")
    return parsed
