import pytest

from taintzero.llm import LLMError
from taintzero.triage import validate_triage


def _valid_result():
    return {
        "verdict": "needs_review",
        "confidence": 0.5,
        "vulnerability_class": "command injection",
        "attack_preconditions": ["input alcança a rota"],
        "evidence": ["fluxo source-to-sink"],
        "impact": "execução de comando",
        "remediation": "evitar shell",
        "rule_improvements": [],
    }


def test_accepts_valid_triage() -> None:
    assert validate_triage(_valid_result())["confidence"] == 0.5


def test_rejects_invalid_confidence() -> None:
    result = _valid_result()
    result["confidence"] = 2
    with pytest.raises(LLMError, match="intervalo"):
        validate_triage(result)
