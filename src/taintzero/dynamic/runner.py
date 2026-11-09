from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .canary import Canary, create_canary
from .events import DynamicEvent, parse_event_stream
from .plan import ExecutionPlan, PlanError

MAX_CAPTURE_CHARS = 1_000_000


@dataclass(frozen=True)
class HarnessResult:
    command: tuple[str, ...]
    canaries: tuple[Canary, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    events: tuple[DynamicEvent, ...] = ()


def build_container_command(
    plan: ExecutionPlan, project_root: Path, runtime: str | None = None
) -> tuple[tuple[str, ...], tuple[Canary, ...]]:
    root = project_root.resolve()
    if not root.is_dir():
        raise PlanError(f"project_root indisponível: {root}")
    executable = _container_runtime(runtime)
    canaries = tuple(create_canary(item.id) for item in plan.inputs)
    command = [
        executable,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(plan.pids_limit),
        "--memory",
        f"{plan.memory_mb}m",
        "--cpus",
        str(plan.cpus),
        "--user",
        "65534:65534",
        "--mount",
        f"type=bind,src={root},dst=/workspace,readonly",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--workdir",
        "/workspace",
    ]
    if plan.instrumentation == "python":
        instrumentation = Path(__file__).with_name("instrumentation").resolve()
        command.extend(
            [
                "--mount",
                f"type=bind,src={instrumentation},dst=/opt/taintzero-instrumentation,readonly",
                "--env",
                "PYTHONPATH=/opt/taintzero-instrumentation",
                "--env",
                f"TAINTZERO_SINK_POLICY={plan.sink_policy}",
            ]
        )
        metadata = {
            item.environment: {"id": canary.id, "input_id": canary.input_id}
            for item, canary in zip(plan.inputs, canaries, strict=True)
        }
        command.extend(
            ["--env", f"TAINTZERO_CANARY_MAP={json.dumps(metadata, separators=(',', ':'))}"]
        )
    for item, canary in zip(plan.inputs, canaries, strict=True):
        command.extend(["--env", f"{item.environment}={canary.marker}"])
    command.extend([plan.image, *plan.command])
    return tuple(command), canaries


def run_in_container(
    plan: ExecutionPlan, project_root: Path, runtime: str | None = None
) -> HarnessResult:
    command, canaries = build_container_command(plan, project_root, runtime)
    _ensure_rootless(command[0])
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=plan.timeout_seconds,
        )
        events, stderr = parse_event_stream(process.stderr[-MAX_CAPTURE_CHARS:])
        events = _known_canary_events(events, canaries)
        return HarnessResult(
            command=command,
            canaries=canaries,
            returncode=process.returncode,
            stdout=process.stdout[-MAX_CAPTURE_CHARS:],
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            events=events,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = _captured_text(exc.stderr)
        events, stderr = parse_event_stream(stderr)
        events = _known_canary_events(events, canaries)
        return HarnessResult(
            command=command,
            canaries=canaries,
            returncode=124,
            stdout=_captured_text(exc.stdout),
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=True,
            events=events,
        )


def _container_runtime(requested: str | None) -> str:
    if requested:
        if Path(requested).name not in {"docker", "podman"}:
            raise PlanError("runtime deve ser docker ou podman")
        resolved = shutil.which(requested)
        if resolved is None:
            raise PlanError(f"runtime não encontrado: {requested}")
        return resolved
    for candidate in ("podman", "docker"):
        if resolved := shutil.which(candidate):
            return resolved
    raise PlanError("Docker ou Podman é necessário para o harness dinâmico")


def _ensure_rootless(executable: str) -> None:
    name = Path(executable).name
    template = "{{.Host.Security.Rootless}}" if name == "podman" else "{{json .SecurityOptions}}"
    try:
        process = subprocess.run(
            [executable, "info", "--format", template],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanError(f"não foi possível verificar runtime rootless: {exc}") from exc
    output = process.stdout.strip().lower()
    rootless = output == "true" if name == "podman" else "rootless" in output
    if process.returncode != 0 or not rootless:
        raise PlanError("o harness exige Docker ou Podman em modo rootless")


def _captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-MAX_CAPTURE_CHARS:]


def _known_canary_events(
    events: tuple[DynamicEvent, ...], canaries: tuple[Canary, ...]
) -> tuple[DynamicEvent, ...]:
    identities = {(canary.id, canary.input_id) for canary in canaries}
    return tuple(
        event
        for event in events
        if event.event == "sink_observed" and (event.canary_id, event.input_id) in identities
    )
