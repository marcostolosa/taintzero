from pathlib import Path

from taintzero.analysis import analyze_taint, index_python_project


def test_module_scope_source_to_sink_is_analyzed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n"
        "value = input('command: ')\n"
        "os.system(value)\n",
        encoding="utf-8",
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert findings[0].source.line == 2
    assert findings[0].sink.line == 3
