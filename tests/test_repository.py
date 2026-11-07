import json
from pathlib import Path

import pytest

from taintzero.repository import (
    RepositoryError,
    prepare_repository,
    profile_repository,
    write_profile,
)


def test_profiles_languages_and_frameworks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "server.ts").write_text("export {};\n", encoding="utf-8")

    profile = profile_repository(tmp_path, str(tmp_path), remote=False)

    assert profile.languages == {"python": 1, "typescript": 1}
    assert profile.frameworks == ["express"]
    assert profile.manifests == ["package.json"]


def test_writes_profile_json(tmp_path: Path) -> None:
    profile = profile_repository(tmp_path, str(tmp_path), remote=False)
    output = tmp_path / "out" / "profile.json"
    write_profile(profile, output)
    assert json.loads(output.read_text(encoding="utf-8"))["remote"] is False


def test_accepts_existing_local_repository(tmp_path: Path) -> None:
    path, remote = prepare_repository(str(tmp_path), tmp_path / "unused")
    assert path == tmp_path.resolve()
    assert remote is False


def test_rejects_credentials_in_clone_url(tmp_path: Path) -> None:
    with pytest.raises(RepositoryError, match="credenciais"):
        prepare_repository("https://token@example.com/repo.git", tmp_path)
