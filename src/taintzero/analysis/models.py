from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml


class ModelError(ValueError):
    pass


@dataclass(frozen=True)
class CallModel:
    symbol: str
    kind: str
    taint: str = "untrusted"
    arguments: tuple[int, ...] = ()
    vulnerability: str | None = None
    required_keywords: tuple[tuple[str, object], ...] = ()
    required_taints: tuple[tuple[int, str], ...] = ()
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    required_types: tuple[tuple[int, str], ...] = ()

    def matches(self, symbol: str) -> bool:
        return fnmatchcase(symbol, self.symbol)


@dataclass(frozen=True)
class ModelRegistry:
    models: tuple[CallModel, ...]
    conservative_unknown_calls: bool = True

    def matching(self, symbol: str, kind: str | None = None) -> tuple[CallModel, ...]:
        return tuple(
            model
            for model in self.models
            if model.matches(symbol) and (kind is None or model.kind == kind)
        )


def load_model_registry(
    paths: list[Path] | tuple[Path, ...],
    *,
    include_defaults: bool = True,
) -> ModelRegistry:
    models = list(DEFAULT_PYTHON_MODELS.models if include_defaults else ())
    conservative = DEFAULT_PYTHON_MODELS.conservative_unknown_calls
    for path in paths:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ModelError(f"não foi possível carregar modelos de {path}: {exc}") from exc
        if not isinstance(document, dict):
            raise ModelError(f"arquivo de modelos deve conter um objeto: {path}")
        version = str(document.get("version", "1"))
        if version != "1":
            raise ModelError(f"versão de modelos não suportada em {path}: {version}")
        settings = document.get("settings") or {}
        if not isinstance(settings, dict):
            raise ModelError(f"settings deve ser um objeto em {path}")
        if "conservative_unknown_calls" in settings:
            value = settings["conservative_unknown_calls"]
            if not isinstance(value, bool):
                raise ModelError(f"conservative_unknown_calls deve ser booleano em {path}")
            conservative = value
        entries = document.get("models") or []
        if not isinstance(entries, list):
            raise ModelError(f"models deve ser uma lista em {path}")
        for index, entry in enumerate(entries, start=1):
            model = _parse_model(path, index, entry)
            models = [
                existing
                for existing in models
                if (existing.symbol, existing.kind, existing.taint)
                != (model.symbol, model.kind, model.taint)
            ]
            models.append(model)
    return ModelRegistry(tuple(models), conservative_unknown_calls=conservative)


def _parse_model(path: Path, index: int, entry: Any) -> CallModel:
    where = f"{path}:models[{index}]"
    if not isinstance(entry, dict):
        raise ModelError(f"modelo deve ser um objeto em {where}")
    symbol = entry.get("symbol")
    kind = entry.get("kind")
    if not isinstance(symbol, str) or not symbol.strip():
        raise ModelError(f"symbol inválido em {where}")
    allowed_kinds = {"source", "sink", "sanitizer", "propagator"}
    if kind not in allowed_kinds:
        raise ModelError(f"kind inválido em {where}: {kind}")
    taint = entry.get("taint", "untrusted")
    if not isinstance(taint, str) or not taint.strip():
        raise ModelError(f"taint inválido em {where}")
    raw_arguments = entry.get("arguments") or []
    if not isinstance(raw_arguments, list) or not all(
        isinstance(argument, int) and argument >= 0 for argument in raw_arguments
    ):
        raise ModelError(f"arguments deve conter índices inteiros não negativos em {where}")
    vulnerability = entry.get("vulnerability")
    if vulnerability is not None and (
        not isinstance(vulnerability, str) or not vulnerability.strip()
    ):
        raise ModelError(f"vulnerability inválida em {where}")
    raw_keywords = entry.get("required_keywords") or {}
    if not isinstance(raw_keywords, dict) or not all(
        isinstance(name, str) and isinstance(value, (str, int, float, bool, type(None)))
        for name, value in raw_keywords.items()
    ):
        raise ModelError(f"required_keywords inválido em {where}")
    raw_required_taints = entry.get("required_taints") or {}
    if not isinstance(raw_required_taints, dict):
        raise ModelError(f"required_taints deve ser um objeto em {where}")
    required_taints: list[tuple[int, str]] = []
    for raw_index, required_taint in raw_required_taints.items():
        try:
            argument_index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ModelError(f"índice inválido em required_taints em {where}") from exc
        if (
            argument_index < 0
            or str(argument_index) != str(raw_index)
            or not isinstance(required_taint, str)
            or not required_taint
        ):
            raise ModelError(f"required_taints inválido em {where}")
        required_taints.append((argument_index, required_taint))
    if required_taints and kind != "sink":
        raise ModelError(f"required_taints só é válido para sinks em {where}")
    raw_cwe = entry.get("cwe") or []
    if not isinstance(raw_cwe, list) or not all(
        isinstance(value, str) and value.startswith("CWE-") and value[4:].isdigit()
        for value in raw_cwe
    ):
        raise ModelError(f"cwe deve conter identificadores CWE-N em {where}")
    raw_owasp = entry.get("owasp") or []
    if not isinstance(raw_owasp, list) or not all(
        isinstance(value, str)
        and len(value) == 8
        and value.startswith("A")
        and value[1:3].isdigit()
        and value[3:] == ":2025"
        for value in raw_owasp
    ):
        raise ModelError(f"owasp deve conter identificadores A00:2025 em {where}")
    raw_required_types = entry.get("required_types") or {}
    if not isinstance(raw_required_types, dict):
        raise ModelError(f"required_types deve ser um objeto em {where}")
    required_types: list[tuple[int, str]] = []
    for raw_index, type_name in raw_required_types.items():
        try:
            argument_index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ModelError(f"índice inválido em required_types em {where}") from exc
        if (
            argument_index < 0
            or str(argument_index) != str(raw_index)
            or not isinstance(type_name, str)
            or not type_name
        ):
            raise ModelError(f"required_types inválido em {where}")
        required_types.append((argument_index, type_name))
    if required_types and kind != "sink":
        raise ModelError(f"required_types só é válido para sinks em {where}")
    return CallModel(
        symbol=symbol,
        kind=kind,
        taint=taint,
        arguments=tuple(raw_arguments),
        vulnerability=vulnerability,
        required_keywords=tuple(raw_keywords.items()),
        required_taints=tuple(sorted(required_taints)),
        cwe=tuple(raw_cwe),
        owasp=tuple(raw_owasp),
        required_types=tuple(sorted(required_types)),
    )


TAINT_KINDS = (
    "code",
    "command",
    "html",
    "path",
    "serialized",
    "sql",
    "template",
    "url",
    "xml",
)
INPUT_SOURCES = (
    "builtins.input",
    "flask.request.get_json",
    "flask.request.args.get",
    "flask.request.args.__getitem__",
    "flask.request.cookies.get",
    "flask.request.cookies.__getitem__",
    "flask.request.form.get",
    "flask.request.form.__getitem__",
    "flask.request.headers.get",
    "flask.request.headers.__getitem__",
    "flask.request.json.get",
    "flask.request.json.__getitem__",
    "flask.request.values.get",
    "flask.request.values.__getitem__",
)

DEFAULT_PYTHON_MODELS = ModelRegistry(
    models=(
        *(CallModel(symbol, "source", taint) for symbol in INPUT_SOURCES for taint in TAINT_KINDS),
        CallModel(
            "os.system", "sink", "command", (0,), "command-injection",
            cwe=("CWE-78",), owasp=("A05:2025",),
        ),
        CallModel(
            "os.popen", "sink", "command", (0,), "command-injection",
            cwe=("CWE-78",), owasp=("A05:2025",),
        ),
        CallModel(
            "builtins.eval", "sink", "code", (0,), "code-injection",
            cwe=("CWE-95",), owasp=("A05:2025",),
        ),
        CallModel(
            "builtins.exec", "sink", "code", (0,), "code-injection",
            cwe=("CWE-94",), owasp=("A05:2025",),
        ),
        CallModel(
            "subprocess.run",
            "sink",
            "command",
            (0,),
            "command-injection",
            (("shell", True),),
            cwe=("CWE-78",),
            owasp=("A05:2025",),
        ),
        CallModel(
            "subprocess.call",
            "sink",
            "command",
            (0,),
            "command-injection",
            (("shell", True),),
            cwe=("CWE-78",),
            owasp=("A05:2025",),
        ),
        CallModel(
            "subprocess.Popen",
            "sink",
            "command",
            (0,),
            "command-injection",
            (("shell", True),),
            cwe=("CWE-78",),
            owasp=("A05:2025",),
        ),
        CallModel(
            "subprocess.check_call",
            "sink",
            "command",
            (0,),
            "command-injection",
            (("shell", True),),
            cwe=("CWE-78",),
            owasp=("A05:2025",),
        ),
        CallModel(
            "subprocess.check_output",
            "sink",
            "command",
            (0,),
            "command-injection",
            (("shell", True),),
            cwe=("CWE-78",),
            owasp=("A05:2025",),
        ),
        CallModel("shlex.quote", "sanitizer", "command", (0,)),
        CallModel("markupsafe.escape", "sanitizer", "html", (0,)),
        CallModel("flask.escape", "sanitizer", "html", (0,)),
        CallModel(
            "flask.make_response", "sink", "html", (0,), "cross-site-scripting",
            cwe=("CWE-79",), owasp=("A05:2025",),
            required_types=((0, "builtins.str"),),
        ),
        CallModel(
            "flask.Response", "sink", "html", (0,), "cross-site-scripting",
            cwe=("CWE-79",), owasp=("A05:2025",),
        ),
        CallModel(
            "markupsafe.Markup", "sink", "html", (0,), "cross-site-scripting",
            cwe=("CWE-79",), owasp=("A05:2025",),
        ),
        *(CallModel(symbol, "sink", "url", arguments, "ssrf", cwe=("CWE-918",),
                    owasp=("A01:2025",)) for symbol, arguments in (
            ("requests.get", (0,)), ("requests.post", (0,)), ("requests.put", (0,)),
            ("requests.patch", (0,)), ("requests.delete", (0,)),
            ("requests.request", (1,)), ("httpx.get", (0,)), ("httpx.post", (0,)),
        )),
        CallModel(
            "builtins.open", "sink", "path", (0,), "path-traversal",
            cwe=("CWE-22",), owasp=("A01:2025",),
        ),
        CallModel(
            "os.open", "sink", "path", (0,), "path-traversal",
            cwe=("CWE-22",), owasp=("A01:2025",),
        ),
        CallModel(
            "pickle.load", "sink", "serialized", (0,), "unsafe-deserialization",
            cwe=("CWE-502",), owasp=("A08:2025",),
        ),
        CallModel(
            "pickle.loads", "sink", "serialized", (0,), "unsafe-deserialization",
            cwe=("CWE-502",), owasp=("A08:2025",),
        ),
        CallModel(
            "yaml.unsafe_load", "sink", "serialized", (0,), "unsafe-deserialization",
            cwe=("CWE-502",), owasp=("A08:2025",),
        ),
        CallModel(
            "db.cursor.execute", "sink", "sql", (0,), "sql-injection",
            cwe=("CWE-89",), owasp=("A05:2025",),
        ),
        CallModel(
            "lxml.etree.XMLParser",
            "source",
            "unsafe-xml-parser",
            required_keywords=(("resolve_entities", True),),
        ),
        CallModel(
            "lxml.etree.fromstring",
            "sink",
            "xml",
            (0,),
            "xml-external-entity",
            required_taints=((1, "unsafe-xml-parser"),),
            cwe=("CWE-611",),
            owasp=("A02:2025",),
        ),
        CallModel(
            "flask.render_template_string",
            "sink",
            "template",
            (0,),
            "server-side-template-injection",
            cwe=("CWE-1336",),
            owasp=("A05:2025",),
        ),
    )
)
