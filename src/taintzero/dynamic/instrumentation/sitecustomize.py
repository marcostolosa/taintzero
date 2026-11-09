"""Dependency-free Python runtime probe loaded automatically through PYTHONPATH.

This file is deliberately standalone: it is mounted read-only into an untrusted
target container and must not import the installed TaintZero package.
"""

from __future__ import annotations

import base64
import builtins
import functools
import inspect
import json
import os
import sys
from urllib.parse import quote

_PREFIX = "TAINTZERO_EVENT "
_AUDIT_SINKS = {
    "os.system": "os.system",
    "os.posix_spawn": "os.posix_spawn",
    "os.posix_spawnp": "os.posix_spawnp",
    "subprocess.Popen": "subprocess.Popen",
    "open": "builtins.open",
    "socket.connect": "socket.connect",
    "socket.getaddrinfo": "socket.getaddrinfo",
}
_BUSY = False


def _load_canaries():
    try:
        metadata = json.loads(os.environ.get("TAINTZERO_CANARY_MAP", "{}"))
    except (TypeError, json.JSONDecodeError):
        return ()
    canaries = []
    if not isinstance(metadata, dict):
        return ()
    for environment, identity in metadata.items():
        marker = os.environ.get(environment)
        if not marker or not isinstance(identity, dict):
            continue
        canaries.append(
            (
                marker,
                str(identity.get("id", "unknown")),
                str(identity.get("input_id", environment)),
            )
        )
    return tuple(canaries)


_CANARIES = _load_canaries()


def _render(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return " ".join(f"{_render(key)}={_render(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_render(item) for item in value)
    return str(value)


def _variants(rendered, marker):
    candidates = {
        "raw": marker,
        "url": quote(marker, safe=""),
        "base64": base64.b64encode(marker.encode()).decode(),
        "json": json.dumps(marker, ensure_ascii=True)[1:-1],
    }
    return [name for name, value in candidates.items() if value in rendered]


def _caller():
    for frame_info in inspect.stack(context=0):
        path = frame_info.filename
        if path == __file__ or path.startswith("<"):
            continue
        path = path.removeprefix("/workspace/")
        return path, frame_info.lineno
    return None, None


def _audit(event, args):
    symbol = _AUDIT_SINKS.get(event)
    if symbol is None:
        return
    _observe(symbol, args)


def _observe(symbol, args):
    global _BUSY
    if _BUSY or not _CANARIES:
        return
    rendered = _render(args)
    matches = []
    for marker, canary_id, input_id in _CANARIES:
        variants = _variants(rendered, marker)
        if variants:
            matches.append((canary_id, input_id, variants))
    if not matches:
        return
    _BUSY = True
    blocked = os.environ.get("TAINTZERO_SINK_POLICY", "block") == "block"
    try:
        path, line = _caller()
        for canary_id, input_id, variants in matches:
            record = {
                "schema_version": "1",
                "event": "sink_observed",
                "canary_id": canary_id,
                "input_id": input_id,
                "symbol": symbol,
                "path": path,
                "line": line,
                "variants": variants,
                "blocked": blocked,
            }
            sys.stderr.write(_PREFIX + json.dumps(record, sort_keys=True) + "\n")
            sys.stderr.flush()
    finally:
        _BUSY = False
    if blocked:
        raise PermissionError(f"TaintZero blocked canary at {symbol}")


def _wrap_function(owner, attribute, symbol):
    original = getattr(owner, attribute, None)
    if original is None or getattr(original, "__taintzero_instrumented__", False):
        return

    @functools.wraps(original)
    def instrumented(*args, **kwargs):
        _observe(symbol, (args, kwargs))
        return original(*args, **kwargs)

    instrumented.__taintzero_instrumented__ = True
    setattr(owner, attribute, instrumented)


def _patch_loaded_modules():
    pickle_module = sys.modules.get("pickle")
    if pickle_module is not None:
        _wrap_function(pickle_module, "loads", "pickle.loads")
    flask_module = sys.modules.get("flask")
    if flask_module is not None:
        _wrap_function(flask_module, "render_template_string", "flask.render_template_string")
        _wrap_function(flask_module, "make_response", "flask.make_response")
    jinja_module = sys.modules.get("jinja2")
    environment = getattr(jinja_module, "Environment", None) if jinja_module else None
    if environment is not None:
        _wrap_function(environment, "from_string", "jinja2.Environment.from_string")


_ORIGINAL_IMPORT = builtins.__import__


def _instrumenting_import(*args, **kwargs):
    module = _ORIGINAL_IMPORT(*args, **kwargs)
    _patch_loaded_modules()
    return module


if _CANARIES:
    builtins.__import__ = _instrumenting_import
    _patch_loaded_modules()
    sys.addaudithook(_audit)
