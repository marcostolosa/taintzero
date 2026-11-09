from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass

from .ir import FlowEdge, FlowNode, Location, ProgramIR
from .models import DEFAULT_PYTHON_MODELS, ModelRegistry


@dataclass(frozen=True)
class TraceStep:
    node: FlowNode
    incoming_edge: str | None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self.node)
        value["incoming_edge"] = self.incoming_edge
        return value


@dataclass(frozen=True)
class RequiredFlow:
    taint: str
    trace: tuple[TraceStep, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "taint": self.taint,
            "trace": [step.to_dict() for step in self.trace],
        }


@dataclass(frozen=True)
class InterproceduralFinding:
    rule_id: str
    vulnerability: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    taint: str
    source: Location
    sink: Location
    trace: tuple[TraceStep, ...]
    requirements: tuple[RequiredFlow, ...]
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "vulnerability": self.vulnerability,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "taint": self.taint,
            "source": asdict(self.source),
            "sink": asdict(self.sink),
            "confidence": self.confidence,
            "trace": [step.to_dict() for step in self.trace],
            "requirements": [requirement.to_dict() for requirement in self.requirements],
        }


def analyze_taint(
    program: ProgramIR, registry: ModelRegistry = DEFAULT_PYTHON_MODELS
) -> list[InterproceduralFinding]:
    edges = list(program.edges)
    sources: list[tuple[str, str, Location]] = []
    sinks: list[
        tuple[
            str,
            str,
            str,
            tuple[str, ...],
            tuple[str, ...],
            Location,
            tuple[tuple[str, str], ...],
        ]
    ] = []
    known_calls = set(program.functions)

    for call in program.calls:
        source_models = tuple(
            model
            for model in registry.matching(call.callee, "source")
            if all(requirement in call.keyword_values for requirement in model.required_keywords)
        )
        for model in source_models:
            source = (call.result_node, model.taint, call.location)
            if source not in sources:
                sources.append(source)

        sink_models = tuple(
            model
            for model in registry.matching(call.callee, "sink")
            if all(requirement in call.keyword_values for requirement in model.required_keywords)
            and all(
                index < len(call.argument_nodes)
                and program.inferred_types.get(call.argument_nodes[index]) == type_name
                for index, type_name in model.required_types
            )
        )
        for model in sink_models:
            required_taints = tuple(
                (call.argument_nodes[index], taint)
                for index, taint in model.required_taints
                if index < len(call.argument_nodes)
            )
            if len(required_taints) != len(model.required_taints):
                continue
            indexes = model.arguments or tuple(range(len(call.argument_nodes)))
            for index in indexes:
                if index < len(call.argument_nodes):
                    edges.append(
                        FlowEdge(call.argument_nodes[index], call.result_node, "sink_argument")
                    )
                    sinks.append(
                        (
                            call.result_node,
                            model.taint,
                            model.vulnerability or "tainted-data-to-sink",
                            model.cwe,
                            model.owasp,
                            call.location,
                            required_taints,
                        )
                    )

        if call.callee in known_calls or source_models or sink_models:
            continue
        sanitizers = registry.matching(call.callee, "sanitizer")
        if sanitizers:
            blocked_taints = tuple(sorted({model.taint for model in sanitizers}))
            indexes = {index for model in sanitizers for index in model.arguments}
            inputs = (
                [
                    call.argument_nodes[index]
                    for index in sorted(indexes)
                    if index < len(call.argument_nodes)
                ]
                if indexes
                else list(call.argument_nodes)
            )
            edges.extend(
                FlowEdge(node, call.result_node, "sanitizer", blocked_taints)
                for node in inputs
            )
            continue
        propagators = registry.matching(call.callee, "propagator")
        if propagators:
            indexes = {index for model in propagators for index in model.arguments}
            inputs = (
                [
                    call.argument_nodes[index]
                    for index in sorted(indexes)
                    if index < len(call.argument_nodes)
                ]
                if indexes
                else list(call.argument_nodes)
            )
        elif registry.conservative_unknown_calls:
            inputs = [*call.argument_nodes]
            if call.receiver_node:
                inputs.append(call.receiver_node)
        else:
            inputs = []
        edges.extend(FlowEdge(node, call.result_node, "external_call") for node in inputs)

    adjacency: dict[str, list[FlowEdge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source].append(edge)

    reachable_by_taint: dict[str, set[str]] = defaultdict(set)
    for source_node, taint, _location in sources:
        reachable_by_taint[taint].update(_reachable(source_node, taint, adjacency))

    findings: list[InterproceduralFinding] = []
    seen_findings: set[tuple[str, str, str]] = set()
    for source_node, taint, source_location in sources:
        predecessor: dict[str, tuple[str, str] | None] = {source_node: None}
        queue = deque([source_node])
        while queue:
            current = queue.popleft()
            for edge in adjacency.get(current, ()):
                if taint in edge.blocked_taints:
                    continue
                if edge.target not in predecessor:
                    predecessor[edge.target] = (current, edge.kind)
                    queue.append(edge.target)

        for (
            sink_node,
            required_taint,
            vulnerability,
            cwe,
            owasp,
            sink_location,
            conditions,
        ) in sinks:
            if required_taint != taint or sink_node not in predecessor:
                continue
            if any(node not in reachable_by_taint[kind] for node, kind in conditions):
                continue
            key = (source_node, sink_node, vulnerability)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            trace = _trace(program, source_node, sink_node, predecessor)
            requirements = _required_flows(program, sources, adjacency, conditions)
            confidence = "exact"
            all_traces = (trace, *(requirement.trace for requirement in requirements))
            if any(
                step.incoming_edge == "external_call"
                or (step.incoming_edge or "").startswith("possible_")
                for current_trace in all_traces
                for step in current_trace
            ):
                confidence = "probable"
            findings.append(
                InterproceduralFinding(
                    rule_id=f"taintzero.python.{vulnerability}",
                    vulnerability=vulnerability,
                    cwe=cwe,
                    owasp=owasp,
                    taint=taint,
                    source=source_location,
                    sink=sink_location,
                    trace=trace,
                    requirements=requirements,
                    confidence=confidence,
                )
            )
    return sorted(findings, key=lambda item: (item.sink.path, item.sink.line, item.rule_id))


def _reachable(
    source: str, taint: str, adjacency: dict[str, list[FlowEdge]]
) -> set[str]:
    reached = {source}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        for edge in adjacency.get(current, ()):
            if taint in edge.blocked_taints or edge.target in reached:
                continue
            reached.add(edge.target)
            queue.append(edge.target)
    return reached


def _required_flows(
    program: ProgramIR,
    sources: list[tuple[str, str, Location]],
    adjacency: dict[str, list[FlowEdge]],
    conditions: tuple[tuple[str, str], ...],
) -> tuple[RequiredFlow, ...]:
    requirements: list[RequiredFlow] = []
    for target, taint in conditions:
        for source, source_taint, _location in sources:
            if source_taint != taint:
                continue
            predecessor: dict[str, tuple[str, str] | None] = {source: None}
            queue = deque([source])
            while queue and target not in predecessor:
                current = queue.popleft()
                for edge in adjacency.get(current, ()):
                    if taint in edge.blocked_taints or edge.target in predecessor:
                        continue
                    predecessor[edge.target] = (current, edge.kind)
                    queue.append(edge.target)
            if target in predecessor:
                requirements.append(
                    RequiredFlow(taint=taint, trace=_trace(program, source, target, predecessor))
                )
                break
    return tuple(requirements)


def _trace(
    program: ProgramIR,
    source: str,
    sink: str,
    predecessor: dict[str, tuple[str, str] | None],
) -> tuple[TraceStep, ...]:
    reversed_steps: list[TraceStep] = []
    current = sink
    while True:
        previous = predecessor[current]
        incoming = previous[1] if previous else None
        reversed_steps.append(TraceStep(program.nodes[current], incoming))
        if current == source:
            break
        if previous is None:
            raise RuntimeError("trace de taint inconsistente")
        current = previous[0]
    reversed_steps.reverse()
    # incoming_edge belongs to the transition into a node, so restore it after reversing.
    return tuple(
        TraceStep(step.node, None if index == 0 else step.incoming_edge)
        for index, step in enumerate(reversed_steps)
    )
