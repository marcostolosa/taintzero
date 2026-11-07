from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import AppConfig
from .context import code_context
from .llm import LLMError, complete_json
from .models import Finding

SYSTEM_PROMPT = """Você é um revisor de segurança de aplicações fazendo triagem de um achado
determinístico do Semgrep. Analise somente as evidências fornecidas. Não invente funções,
fluxos ou contexto. Não gere exploit operacional. Responda com um único objeto JSON válido com:
verdict (true_positive, false_positive ou needs_review), confidence (0 a 1), vulnerability_class,
attack_preconditions (lista), evidence (lista), impact, remediation e rule_improvements (lista).
Quando faltar contexto, use needs_review e diga exatamente qual evidência falta."""


def triage_finding(config: AppConfig, project_root: Path, finding: Finding) -> dict[str, Any]:
    snippet = code_context(
        project_root,
        finding,
        config.analysis.context_lines,
        redact=config.analysis.redact_secrets,
    )
    payload = {
        "rule_id": finding.rule_id,
        "path": finding.path,
        "start": {"line": finding.start.line, "col": finding.start.col},
        "end": {"line": finding.end.line, "col": finding.end.col},
        "message": finding.message,
        "severity": finding.severity,
        "metadata": finding.metadata,
        "dataflow_trace": finding.dataflow_trace,
        "code_context": snippet,
    }
    result = complete_json(config.llm, SYSTEM_PROMPT, json.dumps(payload, ensure_ascii=False))
    return validate_triage(result)


def validate_triage(value: dict[str, Any]) -> dict[str, Any]:
    verdicts = {"true_positive", "false_positive", "needs_review"}
    if value.get("verdict") not in verdicts:
        raise LLMError("Triagem retornou verdict inválido")

    try:
        confidence = float(value["confidence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LLMError("Triagem retornou confidence inválida") from exc
    if not 0 <= confidence <= 1:
        raise LLMError("Triagem retornou confidence fora do intervalo 0..1")

    for field in ("attack_preconditions", "evidence", "rule_improvements"):
        if not isinstance(value.get(field), list) or not all(
            isinstance(item, str) for item in value[field]
        ):
            raise LLMError(f"Triagem retornou {field} inválido")
    for field in ("vulnerability_class", "impact", "remediation"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise LLMError(f"Triagem retornou {field} inválido")

    value["confidence"] = confidence
    return value
