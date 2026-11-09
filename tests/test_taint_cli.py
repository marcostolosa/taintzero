from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_taint_command_writes_machine_readable_report(tmp_path: Path) -> None:
    project = Path(__file__).parent / "fixtures" / "interproc_positive"
    output = tmp_path / "reports" / "taintzero.json"
    graph = tmp_path / "reports" / "taintzero.dot"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintzero.cli",
            "taint",
            str(project),
            "--output",
            str(output),
            "--graph",
            str(graph),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert process.returncode == 0, process.stderr
    assert "Análise interprocedural concluída" in process.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "0.1"
    assert report["engine"] == "taintzero-python"
    assert report["analysis"] == "interprocedural"
    assert report["statistics"]["classes"] == 0
    assert report["statistics"]["findings"] == 1
    assert report["findings"][0]["vulnerability"] == "command-injection"
    assert report["findings"][0]["trace"][-1]["incoming_edge"] == "sink_argument"
    assert graph.read_text(encoding="utf-8").startswith("digraph taintzero {")


def test_analyze_repo_does_not_require_semgrep_by_default(tmp_path: Path) -> None:
    project = Path(__file__).parent / "fixtures" / "interproc_positive"
    output = tmp_path / "repository-report"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintzero.cli",
            "analyze-repo",
            str(project),
            "--offline",
            "--output-dir",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert process.returncode == 0, process.stderr
    assert (output / "repository-profile.json").is_file()
    assert (output / "taintzero.json").is_file()
    assert (output / "taintzero.dot").is_file()
    assert not (output / "semgrep.json").exists()
    report = json.loads((output / "taintzero.json").read_text(encoding="utf-8"))
    assert report["statistics"]["findings"] == 1


def test_harness_defaults_to_safe_plan_without_execution(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = tmp_path / "harness.yml"
    plan.write_text(
        "version: 1\n"
        "image: python:3.13-slim\n"
        "command: [python, -m, pytest, -q]\n"
        "inputs:\n"
        "  - id: http.query.value\n"
        "    environment: TAINTZERO_CANARY_VALUE\n",
        encoding="utf-8",
    )
    output = tmp_path / "harness-report.json"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintzero.cli",
            "harness",
            str(plan),
            "--project-root",
            str(project),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert process.returncode == 0, process.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "planned"
    assert report["sandbox"]["network"] == "none"
    assert report["sandbox"]["project_mount"] == "read-only"
    assert "--network" in report["command"]
    assert "--read-only" in report["command"]
    assert report["canaries"][0]["input_id"] == "http.query.value"
