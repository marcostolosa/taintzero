from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from taintzero.dynamic import DynamicEvent, events_to_jsonl, parse_event_stream


def test_event_stream_extracts_valid_jsonl_and_preserves_target_logs() -> None:
    event = DynamicEvent(
        event="sink_observed",
        canary_id="abc",
        input_id="http.query.command",
        symbol="os.system",
        path="app.py",
        line=12,
        variants=("raw",),
        blocked=True,
    )
    stream = (
        "normal log\n"
        f"TAINTZERO_EVENT {json.dumps(event.to_dict())}\n"
        "TAINTZERO_EVENT not-json\n"
    )

    events, remaining = parse_event_stream(stream)

    assert events == (event,)
    assert remaining == "normal log\nTAINTZERO_EVENT not-json\n"
    assert json.loads(events_to_jsonl(events))["symbol"] == "os.system"


def test_sitecustomize_observes_and_blocks_canary_at_python_open(tmp_path: Path) -> None:
    instrumentation = (
        Path(__file__).parents[1]
        / "src"
        / "taintzero"
        / "dynamic"
        / "instrumentation"
    )
    marker = "TZCANARY_0123456789abcdef0123456789abcdef"
    metadata = {
        "TAINTZERO_CANARY_PATH": {
            "id": "0123456789abcdef0123456789abcdef",
            "input_id": "cli.path",
        }
    }
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(instrumentation),
            "TAINTZERO_CANARY_PATH": marker,
            "TAINTZERO_CANARY_MAP": json.dumps(metadata),
            "TAINTZERO_SINK_POLICY": "block",
        }
    )
    script = "import os\ntry:\n open(os.environ['TAINTZERO_CANARY_PATH'])\nexcept PermissionError:\n pass\n"

    process = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    events, remaining = parse_event_stream(process.stderr)

    assert process.returncode == 0
    assert remaining == ""
    assert len(events) == 1
    assert events[0].symbol == "builtins.open"
    assert events[0].input_id == "cli.path"
    assert "raw" in events[0].variants
    assert events[0].blocked is True
    assert not (tmp_path / marker).exists()


def test_sitecustomize_wraps_pickle_loads_after_import(tmp_path: Path) -> None:
    process = _run_instrumented_python(
        tmp_path,
        "import os, pickle\n"
        "payload = pickle.dumps(os.environ['TAINTZERO_CANARY_VALUE'])\n"
        "try:\n    pickle.loads(payload)\nexcept PermissionError:\n    pass\n",
    )
    events, remaining = parse_event_stream(process.stderr)

    assert process.returncode == 0
    assert remaining == ""
    assert [event.symbol for event in events] == ["pickle.loads"]
    assert events[0].blocked is True


def test_sitecustomize_wraps_template_sink_from_late_import(tmp_path: Path) -> None:
    (tmp_path / "flask.py").write_text(
        "def render_template_string(value):\n    return value\n",
        encoding="utf-8",
    )
    process = _run_instrumented_python(
        tmp_path,
        "import os\nfrom flask import render_template_string\n"
        "try:\n    render_template_string(os.environ['TAINTZERO_CANARY_VALUE'])\n"
        "except PermissionError:\n    pass\n",
    )
    events, remaining = parse_event_stream(process.stderr)

    assert process.returncode == 0
    assert remaining == ""
    assert [event.symbol for event in events] == ["flask.render_template_string"]
    assert events[0].path is not None and events[0].path.endswith("/app.py")


def test_sitecustomize_wraps_flask_html_response_sink(tmp_path: Path) -> None:
    (tmp_path / "flask.py").write_text(
        "def make_response(value):\n    return value\n",
        encoding="utf-8",
    )
    process = _run_instrumented_python(
        tmp_path,
        "import os\nfrom flask import make_response\n"
        "try:\n    make_response(os.environ['TAINTZERO_CANARY_VALUE'])\n"
        "except PermissionError:\n    pass\n",
    )
    events, remaining = parse_event_stream(process.stderr)

    assert process.returncode == 0
    assert remaining == ""
    assert [event.symbol for event in events] == ["flask.make_response"]


def _run_instrumented_python(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    instrumentation = (
        Path(__file__).parents[1]
        / "src"
        / "taintzero"
        / "dynamic"
        / "instrumentation"
    )
    marker = "TZCANARY_0123456789abcdef0123456789abcdef"
    metadata = {
        "TAINTZERO_CANARY_VALUE": {
            "id": "0123456789abcdef0123456789abcdef",
            "input_id": "http.form.value",
        }
    }
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(instrumentation),
            "TAINTZERO_CANARY_VALUE": marker,
            "TAINTZERO_CANARY_MAP": json.dumps(metadata),
            "TAINTZERO_SINK_POLICY": "block",
        }
    )
    script = tmp_path / "app.py"
    script.write_text(source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
