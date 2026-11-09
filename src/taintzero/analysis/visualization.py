from __future__ import annotations

import json
from typing import Any


def report_to_dot(report: dict[str, Any]) -> str:
    """Render a TaintZero report as deterministic Graphviz DOT."""
    lines = [
        "digraph taintzero {",
        '  graph [rankdir="LR", bgcolor="transparent", fontname="sans-serif"];',
        '  node [shape="box", style="rounded,filled", fontname="sans-serif"];',
        '  edge [fontname="sans-serif", fontsize="10"];',
    ]
    for finding_index, finding in enumerate(report.get("findings", [])):
        trace = finding.get("trace") or []
        lines.append(f"  subgraph cluster_{finding_index} {{")
        title = " · ".join(
            str(value)
            for value in (
                finding.get("vulnerability", "finding"),
                finding.get("taint", "taint"),
                finding.get("confidence", "unknown"),
            )
        )
        lines.append(f"    label={_dot_string(title)};")
        lines.append('    color="#94a3b8";')
        for step_index, step in enumerate(trace):
            node_id = f"f{finding_index}_n{step_index}"
            location = step.get("location") or {}
            label = "\n".join(
                part
                for part in (
                    str(step.get("label") or step.get("kind") or "node"),
                    _location_label(location),
                    f"[{step.get('kind', 'unknown')} · static]",
                )
                if part
            )
            color = _node_color(step_index, len(trace))
            lines.append(
                f"    {node_id} [label={_dot_string(label)}, fillcolor={_dot_string(color)}];"
            )
            if step_index:
                previous = f"f{finding_index}_n{step_index - 1}"
                edge_label = str(step.get("incoming_edge") or "flow")
                lines.append(
                    f"    {previous} -> {node_id} [label={_dot_string(edge_label)}];"
                )
        lines.append("  }")
    if not report.get("findings"):
        lines.append('  empty [label="No taint flows found", fillcolor="#e2e8f0"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def _location_label(location: dict[str, Any]) -> str:
    path = location.get("path")
    line = location.get("line")
    if not path:
        return ""
    return f"{path}:{line}" if line is not None else str(path)


def _node_color(index: int, total: int) -> str:
    if index == 0:
        return "#bbf7d0"
    if index == total - 1:
        return "#fecaca"
    return "#dbeafe"


def _dot_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
