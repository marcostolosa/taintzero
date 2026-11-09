from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .analysis import (
    analyze_taint,
    build_evidence_graph,
    index_python_project,
    load_model_registry,
    report_to_dot,
)
from .config import load_config
from .dynamic import (
    build_container_command,
    events_to_jsonl,
    load_execution_plan,
    run_in_container,
)
from .models import parse_findings
from .repository import prepare_repository, profile_repository, write_profile
from .rulesets import (
    COMMUNITY_SOURCES,
    DOWNLOADABLE_PROFILES,
    prepare_rulesets,
    sources_for_profile,
)
from .semgrep_runner import run_semgrep
from .triage import triage_finding

PROVIDERS = [
    ("openai", "OPENAI_API_KEY"),
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("gemini", "GEMINI_API_KEY"),
    ("azure", "AZURE_API_KEY + AZURE_API_BASE"),
    ("bedrock", "credenciais AWS"),
    ("mistral", "MISTRAL_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("ollama", "nenhuma; local"),
    ("lm_studio", "nenhuma; local"),
    ("vllm", "nenhuma; local"),
    ("custom_openai", "definida pelo usuário"),
]

console = Console()
error_console = Console(stderr=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taintzero")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Executa o Semgrep e salva o JSON original")
    scan.add_argument("target", type=Path)
    scan.add_argument("--rules", action="append", default=None)
    scan.add_argument(
        "--rules-profile",
        choices=("local", *DOWNLOADABLE_PROFILES),
        default="local",
    )
    scan.add_argument("--rules-cache", type=Path, default=Path(".taintzero/rulesets"))
    scan.add_argument("--refresh-rules", action="store_true")
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--output", type=Path, required=True)

    analyze = commands.add_parser(
        "analyze-repo", help="Prepara, identifica e analisa um repositório local ou remoto"
    )
    analyze.add_argument("repository", help="Diretório local ou URL Git HTTPS/SSH")
    analyze.add_argument("--ref", dest="revision", help="Branch ou tag para clone remoto")
    analyze.add_argument("--workspace", type=Path, default=Path(".taintzero/repos"))
    analyze.add_argument("--output-dir", type=Path, default=Path("reports/repository"))
    analyze.add_argument("--rules", action="append", default=None)
    analyze.add_argument(
        "--rules-profile",
        choices=("auto", "local", *DOWNLOADABLE_PROFILES),
        default=None,
    )
    analyze.add_argument("--with-semgrep", action="store_true")
    analyze.add_argument("--rules-cache", type=Path, default=Path(".taintzero/rulesets"))
    analyze.add_argument("--refresh-rules", action="store_true")
    analyze.add_argument("--offline", action="store_true", help="Não baixa regras nem consulta o Registry")
    analyze.add_argument("--refresh", action="store_true", help="Refaz um clone remoto existente")
    analyze.add_argument("--llm-config", type=Path)
    analyze.add_argument("--allow-cloud-code", action="store_true")
    analyze.add_argument("--taint-models", action="append", type=Path, default=[])

    triage = commands.add_parser("triage", help="Enriquece achados com uma LLM escolhida")
    triage.add_argument("report", type=Path)
    triage.add_argument("--project-root", type=Path, required=True)
    triage.add_argument("--llm-config", type=Path, required=True)
    triage.add_argument("--output", type=Path, required=True)
    triage.add_argument("--allow-cloud-code", action="store_true")

    taint = commands.add_parser(
        "taint", help="Executa análise de taint interprocedural Python"
    )
    taint.add_argument("target", type=Path)
    taint.add_argument("--output", type=Path, required=True)
    taint.add_argument("--models", action="append", type=Path, default=[])
    taint.add_argument("--graph", type=Path)

    harness = commands.add_parser(
        "harness", help="Planeja ou executa confirmação dinâmica em container isolado"
    )
    harness.add_argument("plan", type=Path)
    harness.add_argument("--project-root", type=Path, required=True)
    harness.add_argument("--output", type=Path, required=True)
    harness.add_argument("--runtime", choices=("docker", "podman"))
    harness.add_argument("--execute", action="store_true")
    harness.add_argument("--events-output", type=Path)
    harness.add_argument("--static-report", type=Path)
    harness.add_argument("--evidence-output", type=Path)

    commands.add_parser("providers", help="Lista os principais provedores")

    rules = commands.add_parser("rules", help="Baixa e inspeciona coleções de regras")
    rules_commands = rules.add_subparsers(dest="rules_command", required=True)
    sync = rules_commands.add_parser("sync", help="Baixa regras para o cache local")
    sync.add_argument("--profile", choices=DOWNLOADABLE_PROFILES, default="full")
    sync.add_argument("--cache", type=Path, default=Path(".taintzero/rulesets"))
    sync.add_argument("--refresh", action="store_true")
    rules_commands.add_parser("list", help="Lista as fontes do perfil full")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "providers":
            table = Table(title="Provedores LLM", header_style="bold cyan")
            table.add_column("Provedor", style="bold")
            table.add_column("Credencial")
            for provider, credential in PROVIDERS:
                table.add_row(provider, credential)
            console.print(table)
            return
        if args.command == "rules":
            _rules(args)
            return
        if args.command == "scan":
            configs = _rule_configs(args)
            report = _scan_with_progress(args.target, configs)
            _write_json(args.output, report)
            console.print(
                "[bold green]Concluído[/]",
                f"{len(report.get('results', []))} achado(s) em",
                args.output,
            )
            return
        if args.command == "analyze-repo":
            _analyze_repository(args)
            return
        if args.command == "triage":
            _triage(args)
            return
        if args.command == "taint":
            _taint(args)
            return
        if args.command == "harness":
            _harness(args)
    except (OSError, RuntimeError, ValueError) as exc:
        error_console.print("[bold red]Erro:[/]", str(exc))
        raise SystemExit(2) from exc


def _triage(args: argparse.Namespace) -> None:
    config = load_config(args.llm_config)
    if not config.llm.is_local and not args.allow_cloud_code:
        raise ValueError(
            "provedor remoto selecionado; confirme o envio de trechos com --allow-cloud-code"
        )

    report = json.loads(args.report.read_text(encoding="utf-8"))
    findings = parse_findings(report)[: config.analysis.max_findings]
    enriched: list[dict[str, Any]] = []
    with _determinate_progress("Triagem por LLM", len(findings)) as (progress, task):
        for finding in findings:
            item = finding.to_dict()
            try:
                item["ai_triage"] = triage_finding(config, args.project_root, finding)
                item["ai_status"] = "completed"
            except RuntimeError as exc:
                item["ai_status"] = "error"
                item["ai_error"] = str(exc)
            enriched.append(item)
            progress.advance(task)

    output = {
        "schema_version": "1.0",
        "source_report": str(args.report),
        "provider": config.llm.provider,
        "model": config.llm.model,
        "findings": enriched,
    }
    _write_json(args.output, output)
    console.print(
        "[bold green]Triagem concluída[/]",
        f"{len(enriched)} achado(s) processado(s) em",
        args.output,
    )


def _taint(args: argparse.Namespace) -> None:
    with console.status("[cyan]Construindo grafo interprocedural Python...", spinner="line"):
        output = _taint_report(args.target, args.models)
    _write_json(args.output, output)
    if args.graph:
        _write_text(args.graph, report_to_dot(output))
    console.print(
        "[bold green]Análise interprocedural concluída[/]",
        f"{len(output['findings'])} achado(s) em",
        args.output,
    )


def _taint_report(target: Path, model_paths: list[Path] | None = None) -> dict[str, Any]:
    program = index_python_project(target)
    registry = load_model_registry(model_paths or [])
    findings = analyze_taint(program, registry)
    return {
        "schema_version": "0.1",
        "engine": "taintzero-python",
        "analysis": "interprocedural",
        "target": str(target),
        "statistics": {
            "nodes": len(program.nodes),
            "edges": len(program.edges),
            "functions": len(program.functions),
            "classes": len(program.classes),
            "calls": len(program.calls),
            "findings": len(findings),
        },
        "diagnostics": list(program.diagnostics),
        "findings": [finding.to_dict() for finding in findings],
    }


def _harness(args: argparse.Namespace) -> None:
    plan = load_execution_plan(args.plan)
    if args.evidence_output and not args.static_report:
        raise ValueError("--evidence-output exige --static-report")
    if args.execute:
        result = run_in_container(plan, args.project_root, args.runtime)
        events_output = args.events_output or args.output.with_suffix(".events.jsonl")
        _write_text(events_output, events_to_jsonl(result.events))
        output = {
            "schema_version": "0.1",
            "mode": "executed",
            "sandbox": _sandbox_policy(),
            "command": list(result.command),
            "canaries": [
                {"id": item.id, "input_id": item.input_id, "marker": item.marker}
                for item in result.canaries
            ],
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "events": [event.to_dict() for event in result.events],
            "events_output": str(events_output),
        }
        if args.static_report:
            static_report = json.loads(args.static_report.read_text(encoding="utf-8"))
            evidence_output = args.evidence_output or args.output.with_name(
                f"{args.output.stem}.evidence.json"
            )
            _write_json(evidence_output, build_evidence_graph(static_report, result.events))
            output["evidence_output"] = str(evidence_output)
    else:
        command, canaries = build_container_command(plan, args.project_root, args.runtime)
        output = {
            "schema_version": "0.1",
            "mode": "planned",
            "sandbox": _sandbox_policy(),
            "command": list(command),
            "canaries": [
                {"id": item.id, "input_id": item.input_id, "marker": item.marker}
                for item in canaries
            ],
        }
    _write_json(args.output, output)
    action = "executado" if args.execute else "planejado; use --execute para executar"
    console.print("[bold green]Harness[/]", action, "em", args.output)


def _sandbox_policy() -> dict[str, object]:
    return {
        "network": "none",
        "root_filesystem": "read-only",
        "project_mount": "read-only",
        "user": "65534:65534",
        "capabilities": "none",
        "no_new_privileges": True,
    }


def _analyze_repository(args: argparse.Namespace) -> None:
    semgrep_enabled = bool(args.with_semgrep or args.rules or args.rules_profile is not None)
    if args.llm_config and not semgrep_enabled:
        raise ValueError("--llm-config ainda exige --with-semgrep nesta versão")
    with console.status("[cyan]Preparando repositório...", spinner="line"):
        repository, remote = prepare_repository(
            args.repository,
            args.workspace,
            revision=args.revision,
            refresh=args.refresh,
        )
    profile = profile_repository(repository, args.repository, remote)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    profile_path = args.output_dir / "repository-profile.json"
    write_profile(profile, profile_path)

    report_path: Path | None = None
    report: dict[str, Any] | None = None
    if semgrep_enabled:
        if args.rules_profile is None:
            args.rules_profile = "auto"
        configs = _rule_configs(args)
        report_path = args.output_dir / "semgrep.json"
        report = _scan_with_progress(repository, configs)
        _write_json(report_path, report)
    with console.status("[cyan]Analisando fluxos Python entre arquivos...", spinner="line"):
        taint_report = _taint_report(repository, args.taint_models)
        _write_json(args.output_dir / "taintzero.json", taint_report)
        _write_text(args.output_dir / "taintzero.dot", report_to_dot(taint_report))
    console.print(
        "[bold green]Análise concluída[/]",
        f"{len(taint_report['findings'])} fluxo(s) interprocedural(is)",
    )
    console.print("Repositório:", repository)
    console.print("Perfil:", profile_path)
    console.print("Taint interprocedural:", args.output_dir / "taintzero.json")
    if report is not None and report_path is not None:
        console.print("Semgrep:", report_path, f"({len(report.get('results', []))} achado(s))")

    if args.llm_config:
        assert report_path is not None
        _triage(
            argparse.Namespace(
                report=report_path,
                project_root=repository,
                llm_config=args.llm_config,
                output=args.output_dir / "triage.json",
                allow_cloud_code=args.allow_cloud_code,
            )
        )


def _rule_configs(args: argparse.Namespace) -> list[str | Path]:
    configs: list[str | Path] = []
    profile = args.rules_profile
    if profile == "auto":
        if not args.offline:
            configs.append("auto")
    elif profile in DOWNLOADABLE_PROFILES:
        configs.extend(
            _prepare_rulesets_with_progress(
                profile,
                args.rules_cache,
                refresh=args.refresh_rules,
                offline=args.offline,
            )
        )
    if args.rules:
        configs.extend(Path(rule).resolve() for rule in args.rules)
    elif profile in ("auto", "local") and Path("rules").is_dir():
        configs.append(Path("rules").resolve())
    if not configs:
        raise ValueError("nenhuma regra disponível; use --rules ou sincronize um --rules-profile")
    return configs


def _rules(args: argparse.Namespace) -> None:
    if args.rules_command == "list":
        table = Table(title="Fontes de regras", header_style="bold cyan")
        table.add_column("Fonte", style="bold")
        table.add_column("Repositório")
        table.add_row("semgrep", "https://github.com/semgrep/semgrep-rules")
        for source in COMMUNITY_SOURCES:
            table.add_row(source.name, source.repository.removesuffix(".git"))
        console.print(table)
        return
    configs = _prepare_rulesets_with_progress(args.profile, args.cache, refresh=args.refresh)
    console.print(
        "[bold green]Rulesets preparados[/]",
        f"{len(configs)} fonte(s) em",
        args.cache.resolve(),
    )


def _prepare_rulesets_with_progress(
    profile: str,
    cache: Path,
    *,
    refresh: bool = False,
    offline: bool = False,
) -> list[Path]:
    total = len(sources_for_profile(profile))
    with _determinate_progress("Preparando rulesets", total) as (progress, task):
        return prepare_rulesets(
            profile,
            cache,
            refresh=refresh,
            offline=offline,
            progress=lambda completed, _total, name: progress.update(
                task,
                completed=completed,
                description=f"Rulesets: {name}",
            ),
        )


def _scan_with_progress(target: Path, configs: list[str | Path]) -> dict[str, Any]:
    with Progress(
        SpinnerColumn("line", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Executando Semgrep", total=None)
        report = run_semgrep(target, configs)
        progress.update(task, description="Semgrep concluído")
        return report


def _determinate_progress(description: str, total: int) -> _ProgressContext:
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    task = progress.add_task(description, total=total)
    return _ProgressContext(progress, task)


class _ProgressContext:
    def __init__(self, progress: Progress, task: int) -> None:
        self.progress = progress
        self.task = task

    def __enter__(self) -> tuple[Progress, int]:
        self.progress.start()
        return self.progress, self.task

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.progress.stop()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


if __name__ == "__main__":
    main()
