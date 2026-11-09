from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from taintzero.dynamic.events import DynamicEvent


def build_evidence_graph(
    report: dict[str, Any], events: Iterable[DynamicEvent] = ()
) -> dict[str, Any]:
    """Convert static traces and runtime observations into one versioned evidence graph."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    sink_index: dict[tuple[str, int], list[str]] = {}

    for finding in report.get("findings", []):
        trace = finding.get("trace") or []
        finding_id = _stable_id("finding", _finding_identity(finding))
        trace_ids: list[str] = []
        for index, step in enumerate(trace):
            location = step.get("location") or {}
            node_id = _stable_id(
                "static",
                finding_id,
                str(index),
                str(step.get("kind")),
                str(location.get("path")),
                str(location.get("line")),
            )
            nodes[node_id] = {
                "id": node_id,
                "type": step.get("kind", "unknown"),
                "label": step.get("label", step.get("kind", "node")),
                "location": location,
                "symbol": step.get("symbol"),
                "provenance": ["static"],
            }
            trace_ids.append(node_id)
            if index:
                edges.append(
                    {
                        "source": trace_ids[index - 1],
                        "target": node_id,
                        "kind": step.get("incoming_edge") or "flow",
                        "provenance": "static",
                    }
                )
        if trace_ids:
            sink_location = trace[-1].get("location") or {}
            path, line = sink_location.get("path"), sink_location.get("line")
            if isinstance(path, str) and isinstance(line, int):
                sink_index.setdefault((_normalized_path(path), line), []).append(trace_ids[-1])
        findings.append(
            {
                "id": finding_id,
                "rule_id": finding.get("rule_id"),
                "taint": finding.get("taint"),
                "cwe": finding.get("cwe", []),
                "owasp": finding.get("owasp", []),
                "trace": trace_ids,
                "dynamic_status": "not_observed",
                "observations": [],
            }
        )

    observations: list[dict[str, Any]] = []
    finding_by_sink = {
        item["trace"][-1]: item for item in findings if item.get("trace")
    }
    for index, event in enumerate(events):
        observation_id = _stable_id(
            "dynamic", event.canary_id, event.symbol, event.path or "", str(event.line), str(index)
        )
        observation = event.to_dict() | {"id": observation_id, "provenance": "dynamic"}
        candidate_sinks = sink_index.get(
            (_normalized_path(event.path or ""), event.line or -1), []
        )
        matched_sinks = [
            sink_id
            for sink_id in candidate_sinks
            if not nodes[sink_id].get("symbol")
            or nodes[sink_id].get("symbol") == event.symbol
        ]
        observation["matched_static_nodes"] = matched_sinks
        observations.append(observation)
        nodes[observation_id] = {
            "id": observation_id,
            "type": "runtime_observation",
            "label": f"{event.input_id} -> {event.symbol}",
            "location": {"path": event.path, "line": event.line},
            "symbol": event.symbol,
            "provenance": ["dynamic"],
        }
        for sink_id in matched_sinks:
            nodes[sink_id]["provenance"] = ["static", "dynamic"]
            edges.append(
                {
                    "source": observation_id,
                    "target": sink_id,
                    "kind": "observed_at",
                    "provenance": "dynamic",
                }
            )
            finding = finding_by_sink[sink_id]
            finding["dynamic_status"] = "confirmed"
            finding["observations"].append(observation_id)

    return {
        "schema_version": "1.0",
        "kind": "taintzero-evidence-graph",
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(
            edges, key=lambda item: (item["source"], item["target"], item["kind"])
        ),
        "findings": findings,
        "observations": observations,
        "coverage": {
            "static_findings": len(findings),
            "confirmed_findings": sum(
                item["dynamic_status"] == "confirmed" for item in findings
            ),
            "runtime_observations": len(observations),
            "correlated_observations": sum(
                bool(item["matched_static_nodes"]) for item in observations
            ),
        },
    }


def _finding_identity(finding: dict[str, Any]) -> str:
    return json.dumps(
        {
            "rule_id": finding.get("rule_id"),
            "taint": finding.get("taint"),
            "source": finding.get("source"),
            "sink": finding.get("sink"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _normalized_path(path: str) -> str:
    value = path.replace("\\", "/")
    return value.removeprefix("/workspace/").lstrip("./")
