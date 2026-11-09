from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, order=True)
class Location:
    path: str
    line: int
    col: int
    end_line: int
    end_col: int

    @classmethod
    def from_ast(cls, root: Path, path: Path, node: object) -> Location:
        return cls(
            path=path.relative_to(root).as_posix(),
            line=int(getattr(node, "lineno", 1)),
            col=int(getattr(node, "col_offset", 0)) + 1,
            end_line=int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
            end_col=int(getattr(node, "end_col_offset", getattr(node, "col_offset", 0))) + 1,
        )


@dataclass(frozen=True)
class FlowNode:
    id: str
    kind: str
    label: str
    location: Location
    symbol: str | None = None


@dataclass(frozen=True)
class FlowEdge:
    source: str
    target: str
    kind: str
    blocked_taints: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionIR:
    symbol: str
    location: Location
    parameters: tuple[str, ...]
    parameter_nodes: tuple[str, ...]
    return_node: str
    binding: str | None = None


@dataclass(frozen=True)
class ClassIR:
    symbol: str
    location: Location
    bases: tuple[str, ...]
    methods: tuple[str, ...]


@dataclass(frozen=True)
class CallSite:
    callee: str
    scope: str
    location: Location
    result_node: str
    positional_arguments: tuple[str, ...]
    keyword_arguments: tuple[tuple[str | None, str], ...] = ()
    keyword_values: tuple[tuple[str, object], ...] = ()
    receiver_node: str | None = None
    possible_dispatch: bool = False

    @property
    def argument_nodes(self) -> tuple[str, ...]:
        return self.positional_arguments + tuple(node for _name, node in self.keyword_arguments)


@dataclass
class ProgramIR:
    root: Path
    nodes: dict[str, FlowNode] = field(default_factory=dict)
    edges: list[FlowEdge] = field(default_factory=list)
    functions: dict[str, FunctionIR] = field(default_factory=dict)
    classes: dict[str, ClassIR] = field(default_factory=dict)
    defined_symbols: set[str] = field(default_factory=set)
    calls: list[CallSite] = field(default_factory=list)
    imports: dict[str, dict[str, str]] = field(default_factory=dict)
    module_environments: dict[str, dict[str, str]] = field(default_factory=dict)
    inferred_types: dict[str, str] = field(default_factory=dict)
    possible_types: dict[str, frozenset[str]] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()

    def add_node(self, node: FlowNode) -> str:
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, source: str, target: str, kind: str) -> None:
        if source != target:
            self.edges.append(FlowEdge(source=source, target=target, kind=kind))

    def types_of(self, node: str) -> frozenset[str]:
        if node in self.possible_types:
            return self.possible_types[node]
        inferred = self.inferred_types.get(node)
        return frozenset((inferred,)) if inferred is not None else frozenset()
