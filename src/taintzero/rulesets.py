from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import yaml


class RulesetError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuleSource:
    name: str
    repository: str
    group: str


SEMGREP_SOURCE = RuleSource(
    name="semgrep",
    repository="https://github.com/semgrep/semgrep-rules.git",
    group="semgrep-all",
)

# Ranked by GitHub stars on 2026-11-07. The official repository and projects that
# only manage or generate rules are intentionally excluded.
COMMUNITY_SOURCES = (
    RuleSource("0xdea", "https://github.com/0xdea/semgrep-rules.git", "community-top10"),
    RuleSource(
        "decurity",
        "https://github.com/Decurity/semgrep-smart-contracts.git",
        "community-top10",
    ),
    RuleSource(
        "trailofbits", "https://github.com/trailofbits/semgrep-rules.git", "community-top10"
    ),
    RuleSource(
        "mindedsecurity-android",
        "https://github.com/mindedsecurity/semgrep-rules-android-security.git",
        "community-top10",
    ),
    RuleSource("elttam", "https://github.com/elttam/semgrep-rules.git", "community-top10"),
    RuleSource("frappe", "https://github.com/frappe/semgrep-rules.git", "community-top10"),
    RuleSource(
        "federicodotta",
        "https://github.com/federicodotta/semgrep-rules.git",
        "community-top10",
    ),
    RuleSource(
        "akabe1", "https://github.com/akabe1/akabe1-semgrep-rules.git", "community-top10"
    ),
    RuleSource(
        "hashicorp",
        "https://github.com/hashicorp-forge/semgrep-rules.git",
        "community-top10",
    ),
    RuleSource(
        "patched-codes",
        "https://github.com/patched-codes/semgrep-rules.git",
        "community-top10",
    ),
)

DOWNLOADABLE_PROFILES = ("semgrep-all", "community-top10", "full")
ProgressCallback = Callable[[int, int, str], None]
PRO_ENGINE_LANGUAGES = {"apex", "elixir"}


def sources_for_profile(profile: str) -> tuple[RuleSource, ...]:
    if profile == "semgrep-all":
        return (SEMGREP_SOURCE,)
    if profile == "community-top10":
        return COMMUNITY_SOURCES
    if profile == "full":
        return (SEMGREP_SOURCE, *COMMUNITY_SOURCES)
    raise RulesetError(f"perfil de regras desconhecido: {profile}")


def prepare_rulesets(
    profile: str,
    cache: Path,
    *,
    refresh: bool = False,
    offline: bool = False,
    progress: ProgressCallback | None = None,
) -> list[Path]:
    sources = sources_for_profile(profile)
    cache = cache.resolve()
    configs: list[Path] = []
    for index, source in enumerate(sources, start=1):
        source_dir = cache / "sources" / source.name
        config_dir = cache / "configs" / source.name
        if offline:
            if not _cache_ready(config_dir):
                raise RulesetError(
                    f"ruleset {source.name!r} não está no cache; execute `taintzero rules sync`"
                )
        else:
            _sync_source(source, source_dir, refresh=refresh)
            if refresh or not _cache_ready(config_dir):
                _compile_source(source, source_dir, config_dir)
        configs.append(config_dir)
        if progress is not None:
            progress(index, len(sources), source.name)
    return configs


def _sync_source(source: RuleSource, destination: Path, *, refresh: bool) -> None:
    git = shutil.which("git")
    if git is None:
        raise RulesetError("Git não está no PATH; ele é necessário para baixar rulesets")
    if destination.exists() and refresh:
        _remove_within(destination, destination.parent)
    if destination.is_dir():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.run(
        [
            git,
            "-c",
            "core.longpaths=true",
            "clone",
            "--depth",
            "1",
            source.repository,
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or "erro desconhecido"
        raise RulesetError(f"falha ao baixar {source.repository}: {detail}")


def _compile_source(
    source: RuleSource, source_dir: Path, config_dir: Path, *, validate: bool = True
) -> None:
    if config_dir.exists():
        _remove_within(config_dir, config_dir.parent)
    config_dir.mkdir(parents=True)
    copied = 0
    discovered = 0
    skipped = 0
    unavailable_rule_ids: list[str] = []
    for candidate in sorted((*source_dir.rglob("*.yml"), *source_dir.rglob("*.yaml"))):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            documents = list(yaml.safe_load_all(candidate.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, yaml.YAMLError):
            skipped += 1
            continue
        if not any(isinstance(document, dict) and isinstance(document.get("rules"), list) for document in documents):
            continue
        discovered += 1
        documents, removed = _filter_unavailable_rules(documents)
        unavailable_rule_ids.extend(removed)
        if not any(
            isinstance(document, dict) and document.get("rules") for document in documents
        ):
            continue
        copied += 1
        suffix = candidate.suffix.lower()
        output = config_dir / f"{copied:05d}-{candidate.stem}{suffix}"
        if removed:
            output.write_text(
                yaml.safe_dump_all(documents, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        else:
            shutil.copyfile(candidate, output)
    if copied == 0:
        raise RulesetError(f"nenhum arquivo de regras válido encontrado em {source.repository}")

    incompatible: list[str] = []
    if validate and not _semgrep_valid((config_dir,)):
        rule_files = sorted((*config_dir.glob("*.yml"), *config_dir.glob("*.yaml")))
        invalid_files = _find_incompatible(rule_files)
        if not invalid_files:
            raise RulesetError(f"conflito entre regras da fonte {source.repository}")
        for rule_file in invalid_files:
            incompatible.append(rule_file.name)
            rule_file.unlink()
    if not _has_rule_files(config_dir):
        raise RulesetError(f"nenhuma regra compatível com o Semgrep em {source.repository}")

    metadata = {
        "source": source.repository,
        "commit": _git_commit(source_dir),
        "discovered_rule_files": discovered,
        "rule_files": copied - len(incompatible),
        "invalid_yaml_files": skipped,
        "incompatible_rule_files": incompatible,
        "unavailable_rule_ids": unavailable_rule_ids,
    }
    (config_dir / "source.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _git_commit(repository: Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return process.stdout.strip() if process.returncode == 0 else "unknown"


def _find_incompatible(configs: list[Path]) -> list[Path]:
    with ThreadPoolExecutor(max_workers=min(4, len(configs))) as executor:
        results = executor.map(lambda config: _semgrep_valid((config,)), configs)
        return [config for config, valid in zip(configs, results, strict=True) if not valid]


def _semgrep_valid(configs: tuple[Path, ...]) -> bool:
    sibling = Path(sys.executable).with_name("semgrep.exe" if os.name == "nt" else "semgrep")
    executable = str(sibling) if sibling.is_file() else shutil.which("semgrep")
    if executable is None:
        raise RulesetError("Semgrep não está no PATH; ele é necessário para validar rulesets")
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    command = [executable, "scan", "--validate"]
    for config in configs:
        command.extend(["--config", str(config)])
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    if process.returncode == 0:
        return True
    if process.returncode == 2:
        return False
    detail = process.stderr.strip() or process.stdout.strip() or "erro desconhecido"
    raise RulesetError(f"Semgrep falhou ao validar ruleset ({process.returncode}): {detail}")


def _has_rule_files(directory: Path) -> bool:
    return directory.is_dir() and any(
        path.is_file() for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern)
    )


def _contains_join_rule(documents: list[object]) -> bool:
    return any(
        isinstance(rule, dict) and rule.get("mode") == "join"
        for document in documents
        if isinstance(document, dict)
        for rule in document.get("rules", [])
    )


def _filter_unavailable_rules(documents: list[object]) -> tuple[list[object], list[str]]:
    removed: list[str] = []
    for document in documents:
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            continue
        available: list[object] = []
        for rule in document["rules"]:
            if not isinstance(rule, dict):
                available.append(rule)
                continue
            languages = {str(language).lower() for language in rule.get("languages", [])}
            requires_pro = bool(languages & PRO_ENGINE_LANGUAGES)
            broken_join_on_windows = os.name == "nt" and rule.get("mode") == "join"
            if requires_pro or broken_join_on_windows:
                removed.append(str(rule.get("id", "unknown")))
            else:
                available.append(rule)
        document["rules"] = available
    return documents, removed


def _cache_ready(directory: Path) -> bool:
    return _has_rule_files(directory) and (directory / "source.json").is_file()


def _remove_within(path: Path, parent: Path) -> None:
    resolved = path.resolve()
    resolved_parent = parent.resolve()
    if resolved.parent != resolved_parent:
        raise RulesetError(f"recusa ao remover caminho fora do cache: {resolved}")
    shutil.rmtree(resolved, onerror=_make_writable_and_retry)


def _make_writable_and_retry(function: Callable[[str], object], path: str, _error: object) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    function(path)
