from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from taintzero.cli import _harness
from taintzero.dynamic import Canary, DynamicEvent, HarnessResult


def test_executed_harness_writes_jsonl_and_merged_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = tmp_path / "harness.yml"
    plan.write_text(
        "version: 1\nimage: python:3.13-slim\ncommand: [python, app.py]\ninputs:\n"
        "  - id: cli.command\n    environment: TAINTZERO_CANARY_COMMAND\n",
        encoding="utf-8",
    )
    static_report = tmp_path / "taintzero.json"
    static_report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "rule_id": "command-injection",
                        "taint": "command",
                        "source": {"path": "app.py", "line": 1},
                        "sink": {"path": "app.py", "line": 4},
                        "trace": [
                            {
                                "kind": "call",
                                "label": "os.system",
                                "symbol": "os.system",
                                "location": {"path": "app.py", "line": 4},
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    canary = Canary(id="canary-id", input_id="cli.command", marker="TZCANARY_canary-id")
    event = DynamicEvent(
        event="sink_observed",
        canary_id=canary.id,
        input_id=canary.input_id,
        symbol="os.system",
        path="app.py",
        line=4,
        variants=("raw",),
        blocked=True,
    )
    monkeypatch.setattr(
        "taintzero.cli.run_in_container",
        lambda *_args: HarnessResult(
            command=("docker", "run"),
            canaries=(canary,),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
            events=(event,),
        ),
    )
    output = tmp_path / "harness-run.json"

    _harness(
        Namespace(
            plan=plan,
            project_root=project,
            output=output,
            runtime=None,
            execute=True,
            events_output=None,
            static_report=static_report,
            evidence_output=None,
        )
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    events = (tmp_path / "harness-run.events.jsonl").read_text(encoding="utf-8")
    evidence = json.loads(
        (tmp_path / "harness-run.evidence.json").read_text(encoding="utf-8")
    )
    assert report["events"][0]["symbol"] == "os.system"
    assert json.loads(events)["input_id"] == "cli.command"
    assert evidence["findings"][0]["dynamic_status"] == "confirmed"
