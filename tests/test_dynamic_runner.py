from pathlib import Path
from types import SimpleNamespace

import pytest

from taintzero.dynamic import (
    PlanError,
    build_container_command,
    load_execution_plan,
    run_in_container,
)


def _plan(tmp_path: Path) -> Path:
    path = tmp_path / "harness.yml"
    path.write_text(
        "version: 1\n"
        "image: python:3.13-slim\n"
        "command: [python, -m, pytest, -q]\n"
        "timeout_seconds: 30\n"
        "memory_mb: 256\n"
        "cpus: 0.5\n"
        "pids_limit: 64\n"
        "inputs:\n"
        "  - id: http.query.command\n"
        "    environment: TAINTZERO_CANARY_COMMAND\n",
        encoding="utf-8",
    )
    return path


def test_builds_restricted_container_command(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = load_execution_plan(_plan(tmp_path))
    monkeypatch.setattr("taintzero.dynamic.runner.shutil.which", lambda name: f"/usr/bin/{name}")

    command, canaries = build_container_command(plan, project, runtime="docker")

    joined = " ".join(command)
    assert command[:3] == ("/usr/bin/docker", "run", "--rm")
    assert "--network none" in joined
    assert "--read-only" in command
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--user 65534:65534" in joined
    assert "--pids-limit 64" in joined
    assert "--memory 256m" in joined
    assert "--cpus 0.5" in joined
    assert f"src={project.resolve()},dst=/workspace,readonly" in joined
    assert "dst=/opt/taintzero-instrumentation,readonly" in joined
    assert "PYTHONPATH=/opt/taintzero-instrumentation" in joined
    assert "TAINTZERO_SINK_POLICY=block" in joined
    assert "TAINTZERO_CANARY_MAP=" in joined
    assert "/tmp:rw,noexec,nosuid,nodev,size=64m" in command
    assert canaries[0].marker in joined
    assert command[-5:] == ("python:3.13-slim", "python", "-m", "pytest", "-q")


def test_runner_captures_result_without_shell(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = load_execution_plan(_plan(tmp_path))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="tests passed", stderr="")

    monkeypatch.setattr("taintzero.dynamic.runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("taintzero.dynamic.runner._ensure_rootless", lambda _runtime: None)
    monkeypatch.setattr("taintzero.dynamic.runner.subprocess.run", fake_run)

    result = run_in_container(plan, project)

    assert result.returncode == 0
    assert result.stdout == "tests passed"
    assert result.timed_out is False
    assert captured["command"] == result.command
    assert captured["timeout"] == 30
    assert "shell" not in captured


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("version: 2\nimage: python\ncommand: ['true']\n", "versão"),
        ("version: 1\nimage: 'bad image'\ncommand: ['true']\n", "image"),
        ("version: 1\nimage: python\ncommand: []\n", "command"),
        (
            (
                "version: 1\nimage: python\ncommand: ['true']\ninputs:\n"
                "  - id: query\n    environment: SECRET\n"
            ),
            "TAINTZERO_CANARY_",
        ),
        (
            "version: 1\nimage: python\ncommand: ['true']\ntimeout_seconds: 0\n",
            "timeout_seconds",
        ),
        (
            "version: 1\nimage: python\ncommand: ['true']\nsink_policy: permit\n",
            "sink_policy",
        ),
    ],
)
def test_rejects_unsafe_execution_plans(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(PlanError, match=message):
        load_execution_plan(path)


def test_rejects_arbitrary_runtime(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = load_execution_plan(_plan(tmp_path))

    with pytest.raises(PlanError, match="docker ou podman"):
        build_container_command(plan, project, runtime="bash")


def test_rejects_rootful_container_runtime(monkeypatch) -> None:
    from taintzero.dynamic.runner import _ensure_rootless

    monkeypatch.setattr(
        "taintzero.dynamic.runner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout='["name=seccomp"]', stderr=""
        ),
    )

    with pytest.raises(PlanError, match="rootless"):
        _ensure_rootless("/usr/bin/docker")
