import json
import stat
import subprocess
from pathlib import Path

import pytest

from taintzero.rulesets import (
    COMMUNITY_SOURCES,
    RulesetError,
    RuleSource,
    _compile_source,
    _contains_join_rule,
    _filter_unavailable_rules,
    _find_incompatible,
    _remove_within,
    _sync_source,
    prepare_rulesets,
    sources_for_profile,
)


def test_full_profile_contains_official_and_ten_community_sources() -> None:
    sources = sources_for_profile("full")
    assert len(COMMUNITY_SOURCES) == 10
    assert len(sources) == 11
    assert sources[0].name == "semgrep"


def test_compiles_only_semgrep_rule_yaml(tmp_path: Path) -> None:
    source = sources_for_profile("semgrep-all")[0]
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "rule.yml").write_text(
        "rules:\n  - id: example\n    languages: [python]\n    message: test\n"
        "    severity: WARNING\n    pattern: print(...)\n",
        encoding="utf-8",
    )
    (source_dir / "workflow.yml").write_text("name: CI\n", encoding="utf-8")
    config_dir = tmp_path / "configs" / "semgrep"

    _compile_source(source, source_dir, config_dir, validate=False)

    assert len(list(config_dir.glob("*.yml"))) == 1
    assert (config_dir / "source.json").is_file()


def test_offline_requires_populated_cache(tmp_path: Path) -> None:
    with pytest.raises(RulesetError, match="não está no cache"):
        prepare_rulesets("semgrep-all", tmp_path, offline=True)


def test_isolates_incompatible_rule_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    files = [tmp_path / name for name in ("a.yml", "bad.yml", "c.yml", "d.yml")]
    monkeypatch.setattr(
        "taintzero.rulesets._semgrep_valid",
        lambda configs: all(config.name != "bad.yml" for config in configs),
    )

    assert _find_incompatible(files) == [tmp_path / "bad.yml"]


def test_detects_join_rule() -> None:
    assert _contains_join_rule([{"rules": [{"id": "joined", "mode": "join"}]}])
    assert not _contains_join_rule([{"rules": [{"id": "taint", "mode": "taint"}]}])


def test_filters_pro_language_without_removing_ce_rules() -> None:
    documents: list[object] = [
        {
            "rules": [
                {"id": "requires-pro", "languages": ["apex"]},
                {"id": "works-in-ce", "languages": ["python"]},
            ]
        }
    ]

    filtered, removed = _filter_unavailable_rules(documents)

    assert removed == ["requires-pro"]
    assert filtered == [{"rules": [{"id": "works-in-ce", "languages": ["python"]}]}]


def test_syncs_local_git_source(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    subprocess.run(["git", "init", "-q", str(upstream)], check=True)
    subprocess.run(["git", "-C", str(upstream), "config", "user.email", "ci@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(upstream), "config", "user.name", "CI"], check=True)
    (upstream / "rule.yml").write_text(_valid_rule("local-sync"), encoding="utf-8")
    subprocess.run(["git", "-C", str(upstream), "add", "rule.yml"], check=True)
    subprocess.run(["git", "-C", str(upstream), "commit", "-qm", "fixture"], check=True)
    destination = tmp_path / "cache" / "source"

    _sync_source(RuleSource("fixture", str(upstream), "test"), destination, refresh=False)

    assert (destination / "rule.yml").is_file()


def test_compiler_filters_rules_semgrep_cannot_load(tmp_path: Path) -> None:
    source = RuleSource("fixture", "local", "test")
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "valid.yml").write_text(_valid_rule("valid-rule"), encoding="utf-8")
    (source_dir / "invalid.yml").write_text(
        "rules:\n  - id: missing-languages\n    message: invalid\n"
        "    severity: WARNING\n    pattern: print(...)\n",
        encoding="utf-8",
    )
    config_dir = tmp_path / "configs" / "fixture"

    _compile_source(source, source_dir, config_dir)

    metadata = json.loads((config_dir / "source.json").read_text(encoding="utf-8"))
    assert metadata["rule_files"] == 1
    assert len(metadata["incompatible_rule_files"]) == 1


def test_progress_reports_real_completed_source_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = RuleSource("cached", "local", "test")
    config_dir = tmp_path / "configs" / source.name
    config_dir.mkdir(parents=True)
    (config_dir / "rule.yml").write_text(_valid_rule("cached"), encoding="utf-8")
    (config_dir / "source.json").write_text("{}\n", encoding="utf-8")
    events: list[tuple[int, int, str]] = []
    monkeypatch.setattr("taintzero.rulesets.sources_for_profile", lambda _profile: (source,))

    prepare_rulesets("fixture", tmp_path, offline=True, progress=lambda *event: events.append(event))

    assert events == [(1, 1, "cached")]


def _valid_rule(rule_id: str) -> str:
    return (
        f"rules:\n  - id: {rule_id}\n    languages: [python]\n"
        "    message: test\n    severity: WARNING\n    pattern: print(...)\n"
    )


def test_removes_read_only_cache_file(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    target = cache / "source"
    target.mkdir(parents=True)
    locked = target / "pack.idx"
    locked.write_text("fixture", encoding="utf-8")
    locked.chmod(stat.S_IREAD)

    _remove_within(target, cache)

    assert not target.exists()
