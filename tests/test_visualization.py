import shutil
import subprocess

import pytest

from taintzero.analysis import report_to_dot


def test_graphviz_report_contains_trace_and_provenance() -> None:
    report = {
        "findings": [
            {
                "vulnerability": "xss",
                "taint": "html",
                "confidence": "exact",
                "trace": [
                    {
                        "kind": "source",
                        "label": 'input "value"',
                        "location": {"path": "app.py", "line": 4},
                        "incoming_edge": None,
                    },
                    {
                        "kind": "call_result",
                        "label": "render()",
                        "location": {"path": "views.py", "line": 9},
                        "incoming_edge": "argument_to_parameter",
                    },
                ],
            }
        ]
    }

    dot = report_to_dot(report)

    assert dot.startswith("digraph taintzero {")
    assert "xss · html · exact" in dot
    assert "app.py:4" in dot
    assert "views.py:9" in dot
    assert "source · static" in dot
    assert 'input \\"value\\"' in dot
    assert 'label="argument_to_parameter"' in dot


def test_empty_report_still_produces_valid_graph() -> None:
    dot = report_to_dot({"findings": []})

    assert "No taint flows found" in dot
    assert dot.endswith("}\n")


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz não está instalado")
def test_graphviz_can_render_generated_dot() -> None:
    dot = report_to_dot({"findings": []})

    process = subprocess.run(
        [shutil.which("dot") or "dot", "-Tsvg"],
        input=dot,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert process.returncode == 0, process.stderr
    assert process.stdout.lstrip().startswith("<?xml")
    assert "<svg" in process.stdout
