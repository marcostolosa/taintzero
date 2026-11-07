from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import load_config
from .models import parse_findings
from .repository import prepare_repository, profile_repository, write_profile
from .rulesets import COMMUNITY_SOURCES, DOWNLOADABLE_PROFILES, prepare_rulesets
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
        default="auto",
    )
    analyze.add_argument("--rules-cache", type=Path, default=Path(".taintzero/rulesets"))
    analyze.add_argument("--refresh-rules", action="store_true")
    analyze.add_argument("--offline", action="store_true", help="Não baixa regras nem consulta o Registry")
    analyze.add_argument("--refresh", action="store_true", help="Refaz um clone remoto existente")
    analyze.add_argument("--llm-config", type=Path)
    analyze.add_argument("--allow-cloud-code", action="store_true")

    triage = commands.add_parser("triage", help="Enriquece achados com uma LLM escolhida")
    triage.add_argument("report", type=Path)
    triage.add_argument("--project-root", type=Path, required=True)
    triage.add_argument("--llm-config", type=Path, required=True)
    triage.add_argument("--output", type=Path, required=True)
    triage.add_argument("--allow-cloud-code", action="store_true")

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
            for provider, credential in PROVIDERS:
                print(f"{provider:<16} {credential}")
            return
        if args.command == "rules":
            _rules(args)
            return
        if args.command == "scan":
            configs = _rule_configs(args)
            report = run_semgrep(args.target, configs)
            _write_json(args.output, report)
            print(f"{len(report.get('results', []))} achado(s) em {args.output}")
            return
        if args.command == "analyze-repo":
            _analyze_repository(args)
            return
        if args.command == "triage":
            _triage(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
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
    for finding in findings:
        item = finding.to_dict()
        try:
            item["ai_triage"] = triage_finding(config, args.project_root, finding)
            item["ai_status"] = "completed"
        except RuntimeError as exc:
            item["ai_status"] = "error"
            item["ai_error"] = str(exc)
        enriched.append(item)

    output = {
        "schema_version": "1.0",
        "source_report": str(args.report),
        "provider": config.llm.provider,
        "model": config.llm.model,
        "findings": enriched,
    }
    _write_json(args.output, output)
    print(f"{len(enriched)} achado(s) processado(s) em {args.output}")


def _analyze_repository(args: argparse.Namespace) -> None:
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

    configs = _rule_configs(args)

    report_path = args.output_dir / "semgrep.json"
    report = run_semgrep(repository, configs)
    _write_json(report_path, report)
    print(
        f"repositório preparado em {repository}; "
        f"{len(report.get('results', []))} achado(s); perfil em {profile_path}"
    )

    if args.llm_config:
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
            prepare_rulesets(
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
        print(f"{'semgrep':<24} https://github.com/semgrep/semgrep-rules")
        for source in COMMUNITY_SOURCES:
            print(f"{source.name:<24} {source.repository.removesuffix('.git')}")
        return
    configs = prepare_rulesets(args.profile, args.cache, refresh=args.refresh)
    print(f"{len(configs)} fonte(s) preparadas em {args.cache.resolve()}")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
