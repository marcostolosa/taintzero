from pathlib import Path

import pytest

from taintzero.analysis import (
    ModelError,
    analyze_taint,
    index_python_project,
    load_model_registry,
)


def test_custom_models_drive_analysis_without_semgrep(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from company.web import get_input\n"
        "from company.shell import execute\n"
        "def route():\n"
        "    execute(get_input())\n",
        encoding="utf-8",
    )
    models = tmp_path / "models.yml"
    models.write_text(
        "version: 1\n"
        "models:\n"
        "  - symbol: company.web.get_input\n"
        "    kind: source\n"
        "    taint: company-input\n"
        "  - symbol: company.shell.execute\n"
        "    kind: sink\n"
        "    taint: company-input\n"
        "    arguments: [0]\n"
        "    vulnerability: company-command-injection\n",
        encoding="utf-8",
    )

    registry = load_model_registry([models], include_defaults=False)
    findings = analyze_taint(index_python_project(project), registry)

    assert len(findings) == 1
    assert findings[0].vulnerability == "company-command-injection"
    assert findings[0].taint == "company-input"


def test_model_file_can_disable_unknown_call_propagation(tmp_path: Path) -> None:
    models = tmp_path / "models.yml"
    models.write_text(
        "version: 1\nsettings:\n  conservative_unknown_calls: false\nmodels: []\n",
        encoding="utf-8",
    )

    registry = load_model_registry([models])

    assert registry.conservative_unknown_calls is False


def test_source_model_honors_required_keywords(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from company import source, sink\n"
        "sink(source(trusted=True))\n"
        "sink(source(trusted=False))\n",
        encoding="utf-8",
    )
    models = tmp_path / "models.yml"
    models.write_text(
        "version: 1\nmodels:\n"
        "  - symbol: company.source\n    kind: source\n    taint: input\n"
        "    required_keywords: {trusted: false}\n"
        "  - symbol: company.sink\n    kind: sink\n    taint: input\n"
        "    arguments: [0]\n    vulnerability: test-flow\n",
        encoding="utf-8",
    )

    findings = analyze_taint(
        index_python_project(project),
        load_model_registry([models], include_defaults=False),
    )

    assert len(findings) == 1
    assert findings[0].source.line == 3


def test_model_dsl_loads_conjunctive_sink_taint_requirements(tmp_path: Path) -> None:
    models = tmp_path / "models.yml"
    models.write_text(
        "version: 1\nmodels:\n"
        "  - symbol: parser.parse\n    kind: sink\n    taint: xml\n"
        "    arguments: [0]\n    vulnerability: xxe\n"
        "    required_taints: {1: unsafe-parser}\n"
        "    required_types: {0: builtins.str}\n"
        "    cwe: [CWE-611]\n    owasp: ['A02:2025']\n",
        encoding="utf-8",
    )

    registry = load_model_registry([models], include_defaults=False)

    assert registry.models[0].required_taints == ((1, "unsafe-parser"),)
    assert registry.models[0].required_types == ((0, "builtins.str"),)
    assert registry.models[0].cwe == ("CWE-611",)
    assert registry.models[0].owasp == ("A02:2025",)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("version: 2\n", "versão"),
        ("version: 1\nmodels: invalid\n", "models deve ser uma lista"),
        (
            "version: 1\nmodels:\n  - symbol: example.call\n    kind: invalid\n",
            "kind inválido",
        ),
        (
            (
                "version: 1\nmodels:\n  - symbol: example.call\n"
                "    kind: sink\n    arguments: [-1]\n"
            ),
            "índices inteiros não negativos",
        ),
        (
            (
                "version: 1\nmodels:\n  - symbol: example.call\n"
                "    kind: source\n    required_taints: {0: state}\n"
            ),
            "só é válido para sinks",
        ),
        (
            (
                "version: 1\nmodels:\n  - symbol: example.call\n"
                "    kind: sink\n    cwe: [78]\n"
            ),
            "CWE-N",
        ),
        (
            (
                "version: 1\nmodels:\n  - symbol: example.call\n"
                "    kind: sink\n    owasp: ['A05:2021']\n"
            ),
            "A00:2025",
        ),
    ],
)
def test_rejects_invalid_model_files(
    tmp_path: Path, content: str, message: str
) -> None:
    models = tmp_path / "models.yml"
    models.write_text(content, encoding="utf-8")

    with pytest.raises(ModelError, match=message):
        load_model_registry([models])
