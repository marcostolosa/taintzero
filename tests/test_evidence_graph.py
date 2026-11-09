from taintzero.analysis import build_evidence_graph
from taintzero.dynamic import DynamicEvent


def _report() -> dict[str, object]:
    return {
        "findings": [
            {
                "rule_id": "taintzero.python.command-injection",
                "taint": "command",
                "source": {"path": "app.py", "line": 4},
                "sink": {"path": "app.py", "line": 8},
                "trace": [
                    {
                        "kind": "call",
                        "label": "request.args.get",
                        "location": {"path": "app.py", "line": 4},
                        "incoming_edge": None,
                    },
                    {
                        "kind": "call",
                        "label": "os.system",
                        "symbol": "os.system",
                        "location": {"path": "app.py", "line": 8},
                        "incoming_edge": "sink_argument",
                    },
                ],
            }
        ]
    }


def test_dynamic_observation_confirms_matching_static_sink() -> None:
    event = DynamicEvent(
        event="sink_observed",
        canary_id="canary",
        input_id="http.query.command",
        symbol="os.system",
        path="/workspace/app.py",
        line=8,
        variants=("raw",),
        blocked=True,
    )

    graph = build_evidence_graph(_report(), [event])

    assert graph["kind"] == "taintzero-evidence-graph"
    assert graph["coverage"] == {
        "static_findings": 1,
        "confirmed_findings": 1,
        "runtime_observations": 1,
        "correlated_observations": 1,
    }
    assert graph["findings"][0]["dynamic_status"] == "confirmed"
    assert graph["observations"][0]["matched_static_nodes"]
    assert any(edge["kind"] == "observed_at" for edge in graph["edges"])
    sink = next(
        node
        for node in graph["nodes"]
        if node.get("symbol") == "os.system" and node["type"] == "call"
    )
    assert sink["provenance"] == ["static", "dynamic"]
    assert any(node["type"] == "runtime_observation" for node in graph["nodes"])


def test_unmatched_observation_does_not_downgrade_static_finding() -> None:
    event = DynamicEvent(
        event="sink_observed",
        canary_id="canary",
        input_id="http.query.command",
        symbol="os.system",
        path="other.py",
        line=99,
    )

    graph = build_evidence_graph(_report(), [event])

    assert graph["findings"][0]["dynamic_status"] == "not_observed"
    assert graph["coverage"]["confirmed_findings"] == 0
    assert graph["coverage"]["correlated_observations"] == 0
