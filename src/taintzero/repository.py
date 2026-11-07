from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class RepositoryError(RuntimeError):
    pass


SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
}

EXTENSION_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
}

MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "composer.json",
    "Gemfile",
    "Cargo.toml",
}

FRAMEWORK_SIGNALS = {
    "django": ("django",),
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "express": ('"express"', "express@"),
    "nextjs": ('"next"', "next@"),
    "nestjs": ("@nestjs/",),
    "spring": ("spring-boot", "org.springframework"),
    "gin": ("github.com/gin-gonic/gin",),
    "echo": ("github.com/labstack/echo",),
    "fiber": ("github.com/gofiber/fiber",),
    "laravel": ("laravel/framework",),
    "symfony": ("symfony/framework-bundle",),
    "rails": ("rails",),
    "sinatra": ("sinatra",),
    "aspnet": ("microsoft.aspnetcore",),
}


@dataclass(frozen=True)
class RepositoryProfile:
    source: str
    path: str
    remote: bool
    revision: str | None
    languages: dict[str, int]
    frameworks: list[str]
    manifests: list[str]
    files_inspected: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def prepare_repository(
    source: str,
    workspace: Path,
    revision: str | None = None,
    refresh: bool = False,
) -> tuple[Path, bool]:
    local = Path(source).expanduser()
    if local.exists():
        if not local.is_dir():
            raise RepositoryError(f"O caminho não é um diretório: {local}")
        return local.resolve(), False

    if not _is_remote(source):
        raise RepositoryError("Informe um diretório existente ou uma URL Git HTTPS/SSH")
    _validate_remote(source)
    git = shutil.which("git")
    if git is None:
        raise RepositoryError("Git não está no PATH")

    workspace.mkdir(parents=True, exist_ok=True)
    workspace = workspace.resolve()
    hooks_directory = workspace / ".disabled-git-hooks"
    hooks_directory.mkdir(exist_ok=True)
    target = workspace / _repository_key(source, revision)
    if target.exists():
        if not refresh:
            return target.resolve(), True
        target.resolve().relative_to(workspace)
        if target.is_symlink():
            target.unlink()
        else:
            shutil.rmtree(target)

    command = [
        git,
        "-c",
        f"core.hooksPath={hooks_directory}",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
    ]
    if revision:
        command.extend(["--branch", revision])
    command.extend([source, str(target)])
    environment = os.environ.copy()
    environment["GIT_LFS_SKIP_SMUDGE"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )
    if process.returncode != 0:
        detail = _sanitize_git_error(process.stderr.strip(), source)
        raise RepositoryError(f"Falha ao clonar repositório: {detail or 'erro desconhecido'}")
    return target.resolve(), True


def profile_repository(path: Path, source: str, remote: bool) -> RepositoryProfile:
    language_counts: dict[str, int] = {}
    manifests: list[str] = []
    manifest_text: list[str] = []
    files_inspected = 0

    for file in path.rglob("*"):
        relative = file.relative_to(path)
        if not file.is_file() or any(part in SKIP_DIRECTORIES for part in relative.parts[:-1]):
            continue
        files_inspected += 1
        language = EXTENSION_LANGUAGES.get(file.suffix.lower())
        if language:
            language_counts[language] = language_counts.get(language, 0) + 1
        if file.name in MANIFEST_NAMES or file.suffix.lower() == ".csproj":
            manifests.append(relative.as_posix())
            if file.stat().st_size <= 2_000_000:
                manifest_text.append(file.read_text(encoding="utf-8", errors="replace").lower())

    combined = "\n".join(manifest_text)
    frameworks = sorted(
        framework
        for framework, signals in FRAMEWORK_SIGNALS.items()
        if any(signal in combined for signal in signals)
    )
    return RepositoryProfile(
        source=_public_source(source),
        path=str(path),
        remote=remote,
        revision=_git_revision(path),
        languages=dict(sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))),
        frameworks=frameworks,
        manifests=sorted(manifests),
        files_inspected=files_inspected,
    )


def write_profile(profile: RepositoryProfile, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(profile.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _is_remote(source: str) -> bool:
    return source.startswith(("https://", "ssh://", "git@"))


def _validate_remote(source: str) -> None:
    if not source.startswith("https://"):
        return
    parsed = urlsplit(source)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RepositoryError(
            "Não coloque credenciais ou tokens na URL; configure um Git credential manager"
        )


def _repository_key(source: str, revision: str | None) -> str:
    clean = source.rstrip("/").removesuffix(".git")
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", clean.rsplit("/", 1)[-1].rsplit(":", 1)[-1])
    digest = sha256(f"{source}\0{revision or ''}".encode()).hexdigest()[:10]
    return f"{name or 'repository'}-{digest}"


def _public_source(source: str) -> str:
    if "://" not in source:
        return source
    parsed = urlsplit(source)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _sanitize_git_error(message: str, source: str) -> str:
    return message.replace(source, _public_source(source))


def _git_revision(path: Path) -> str | None:
    git = shutil.which("git")
    if git is None or not (path / ".git").exists():
        return None
    process = subprocess.run(
        [git, "-C", str(path), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return process.stdout.strip() if process.returncode == 0 else None
