from pathlib import Path

import pytest

from taintzero.rulesets import (
    COMMUNITY_SOURCES,
    RulesetError,
    _compile_source,
    _contains_join_rule,
    _find_incompatible,
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
