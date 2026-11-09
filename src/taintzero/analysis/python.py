from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .ir import CallSite, ClassIR, FlowNode, FunctionIR, Location, ProgramIR


class PythonAnalysisError(RuntimeError):
    pass


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".taintzero",
    ".tox",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "venv",
}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
EXTERNAL_RETURN_TYPES = {
    "builtins.str": "builtins.str",
    "builtins.str.replace": "builtins.str",
    "cx_Oracle.connect": "db.connection",
    "flask.request.args.__getitem__": "builtins.str",
    "flask.request.args.get": "builtins.str",
    "flask.request.cookies.__getitem__": "builtins.str",
    "flask.request.cookies.get": "builtins.str",
    "flask.request.form.__getitem__": "builtins.str",
    "flask.request.form.get": "builtins.str",
    "flask.request.get_json": "builtins.dict",
    "flask.request.headers.__getitem__": "builtins.str",
    "flask.request.headers.get": "builtins.str",
    "psycopg2.connect": "db.connection",
    "sqlite3.connect": "db.connection",
    "db.connection.cursor": "db.cursor",
}


@dataclass(frozen=True)
class _FunctionSource:
    symbol: str
    module: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    owner_class: str | None = None
    binding: str | None = None


def index_python_project(root: Path) -> ProgramIR:
    root = root.resolve()
    if not root.is_dir():
        raise PythonAnalysisError(f"diretório de projeto indisponível: {root}")

    program = ProgramIR(root=root)
    sources: list[_FunctionSource] = []
    syntax_errors: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRECTORIES for part in relative.parts):
            continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                syntax_errors.append(f"{relative}: arquivo excede {MAX_SOURCE_BYTES} bytes")
                continue
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            syntax_errors.append(f"{path.relative_to(root)}: {exc}")
            continue
        module = _module_name(root, path)
        program.imports[module] = _imports(module, tree)
        program.classes.update(_discover_classes(root, module, path, tree, program.imports[module]))
        sources.extend(_discover_functions(module, path, tree))

    program.defined_symbols.update(program.classes)
    program.defined_symbols.update(source.symbol for source in sources)
    for source in sources:
        _FunctionBuilder(program, source).build()

    _connect_calls(program)
    if syntax_errors:
        # Partial projects are intentionally accepted and diagnostics remain machine-readable.
        program.diagnostics = tuple(syntax_errors)
    return program


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__root__"


def _imports(module: str, tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    package = module.rsplit(".", 1)[0] if "." in module else ""
    for statement in _module_statements(tree.body):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                result[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            base = statement.module or ""
            if statement.level:
                current = package.split(".") if package else []
                keep = max(0, len(current) - statement.level + 1)
                base = ".".join([*current[:keep], *([base] if base else [])])
            for alias in statement.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = ".".join(
                        part for part in (base, alias.name) if part
                    )
    return result


def _module_statements(statements: list[ast.stmt]):
    for statement in statements:
        yield statement
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field, None)
            if isinstance(nested, list):
                yield from _module_statements(nested)
        if isinstance(statement, ast.Try):
            for handler in statement.handlers:
                yield from _module_statements(handler.body)


def _discover_functions(
    module: str, path: Path, tree: ast.Module
) -> list[_FunctionSource]:
    module_body = ast.FunctionDef(
        name="__module__",
        args=ast.arguments(
            posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]
        ),
        body=tree.body,
        decorator_list=[],
    )
    ast.copy_location(module_body, tree.body[0] if tree.body else tree)
    ast.fix_missing_locations(module_body)
    functions: list[_FunctionSource] = [
        _FunctionSource(
            f"{module}.__module__", module, path, module_body, binding="module"
        )
    ]
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(_FunctionSource(f"{module}.{statement.name}", module, path, statement))
        elif isinstance(statement, ast.ClassDef):
            owner = f"{module}.{statement.name}"
            for member in statement.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    decorators = {_expression_name(item) for item in member.decorator_list}
                    binding = "static" if "staticmethod" in decorators else "instance"
                    if "classmethod" in decorators:
                        binding = "class"
                    functions.append(
                        _FunctionSource(
                            f"{owner}.{member.name}",
                            module,
                            path,
                            member,
                            owner_class=owner,
                            binding=binding,
                        )
                    )
    return functions


def _discover_classes(
    root: Path,
    module: str,
    path: Path,
    tree: ast.Module,
    imports: dict[str, str],
) -> dict[str, ClassIR]:
    classes: dict[str, ClassIR] = {}
    for statement in tree.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        symbol = f"{module}.{statement.name}"
        bases = tuple(
            _resolve_module_name(module, imports, name)
            for base in statement.bases
            if (name := _expression_name(base)) is not None
        )
        methods = tuple(
            f"{symbol}.{member.name}"
            for member in statement.body
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        classes[symbol] = ClassIR(
            symbol=symbol,
            location=Location.from_ast(root, path, statement),
            bases=bases,
            methods=methods,
        )
    return classes


def _resolve_module_name(module: str, imports: dict[str, str], name: str) -> str:
    head, separator, tail = name.partition(".")
    if head in imports:
        return imports[head] + (separator + tail if tail else "")
    return f"{module}.{name}"


class _FunctionBuilder:
    def __init__(self, program: ProgramIR, source: _FunctionSource) -> None:
        self.program = program
        self.source = source
        self.environment = (
            {}
            if source.binding == "module"
            else program.module_environments.get(source.module, {}).copy()
        )
        self.node_types = {
            node: frozenset(types) for node, types in program.possible_types.items()
        }
        for node, inferred_type in program.inferred_types.items():
            self.node_types.setdefault(node, frozenset((inferred_type,)))
        self.object_ids: dict[str, str] = {}
        self.fields: dict[str, str] = {}
        self.counter = 0
        self.versions: dict[str, int] = {}
        self.return_node = self._node("return", source.node, "return", source.symbol)

    def build(self) -> None:
        arguments = [
            *self.source.node.args.posonlyargs,
            *self.source.node.args.args,
            *self.source.node.args.kwonlyargs,
        ]
        parameter_nodes = []
        for position, argument in enumerate(arguments):
            node = self._variable(argument.arg, argument, "parameter")
            self.environment[argument.arg] = node
            self.object_ids[node] = node
            inferred_type = self._parameter_type(argument, position)
            if inferred_type:
                self.node_types[node] = frozenset((inferred_type,))
            parameter_nodes.append(node)
        if self.source.node.args.vararg:
            argument = self.source.node.args.vararg
            node = self._variable(argument.arg, argument, "parameter")
            self.environment[argument.arg] = node
            parameter_nodes.append(node)
            arguments.append(argument)
        if self.source.node.args.kwarg:
            argument = self.source.node.args.kwarg
            node = self._variable(argument.arg, argument, "parameter")
            self.environment[argument.arg] = node
            parameter_nodes.append(node)
            arguments.append(argument)

        self.program.functions[self.source.symbol] = FunctionIR(
            symbol=self.source.symbol,
            location=self._location(self.source.node),
            parameters=tuple(argument.arg for argument in arguments),
            parameter_nodes=tuple(parameter_nodes),
            return_node=self.return_node,
            binding=self.source.binding,
        )
        self._statements(self.source.node.body)
        self.program.possible_types.update(self.node_types)
        self.program.inferred_types.update(
            {
                node: next(iter(types))
                for node, types in self.node_types.items()
                if len(types) == 1
            }
        )
        if self.source.binding == "module":
            self.program.module_environments[self.source.module] = self.environment.copy()

    def _statements(self, statements: list[ast.stmt]) -> bool:
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self._expression(statement.value) if statement.value else None
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    self._assign(target, value)
            elif isinstance(statement, ast.AugAssign):
                old = self._expression(statement.target)
                value = self._expression(statement.value)
                expression = self._node("expression", statement, type(statement.op).__name__)
                self.program.add_edge(old, expression, "operand")
                self.program.add_edge(value, expression, "operand")
                self._assign(statement.target, expression)
            elif isinstance(statement, ast.Return) and statement.value is not None:
                self.program.add_edge(self._expression(statement.value), self.return_node, "return")
                return False
            elif isinstance(statement, ast.Return):
                return False
            elif isinstance(statement, ast.Raise):
                if statement.exc is not None:
                    self._expression(statement.exc)
                if statement.cause is not None:
                    self._expression(statement.cause)
                return False
            elif isinstance(statement, ast.Expr):
                self._expression(statement.value)
            elif isinstance(statement, ast.If):
                self._expression(statement.test)
                if not self._branch(statement.body, statement.orelse, statement):
                    return False
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                iterator = self._expression(statement.iter)
                self._assign(statement.target, iterator)
                if not self._branch(statement.body, statement.orelse, statement):
                    return False
            elif isinstance(statement, ast.While):
                self._expression(statement.test)
                if not self._branch(statement.body, statement.orelse, statement):
                    return False
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    value = self._expression(item.context_expr)
                    if item.optional_vars:
                        self._assign(item.optional_vars, value)
                if not self._statements(statement.body):
                    return False
            elif isinstance(statement, ast.Try):
                branches = [statement.body, *(handler.body for handler in statement.handlers)]
                # Try/except/else/finally needs distinct exceptional and normal successors.
                # Preserve terminated branch state for finally and stay conservative until the
                # dedicated CFG represents those edges explicitly.
                self._multi_branch(branches, statement, keep_terminated=True)
                self._statements(statement.orelse)
                self._statements(statement.finalbody)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
        return True

    def _branch(self, left: list[ast.stmt], right: list[ast.stmt], node: ast.AST) -> bool:
        return self._multi_branch([left, right], node)

    def _multi_branch(
        self,
        branches: list[list[ast.stmt]],
        node: ast.AST,
        *,
        keep_terminated: bool = False,
    ) -> bool:
        before = self.environment.copy()
        before_fields = self.fields.copy()
        outcomes: list[dict[str, str]] = []
        field_outcomes: list[dict[str, str]] = []
        for branch in branches:
            self.environment = before.copy()
            self.fields = before_fields.copy()
            falls_through = self._statements(branch)
            if falls_through or keep_terminated:
                outcomes.append(self.environment.copy())
                field_outcomes.append(self.fields.copy())
        self.environment = before
        self.fields = before_fields
        if not outcomes:
            return False
        for name in sorted(set().union(*(outcome.keys() for outcome in outcomes))):
            candidates = {outcome.get(name, before.get(name)) for outcome in outcomes}
            candidates.discard(None)
            if len(candidates) == 1:
                self.environment[name] = next(iter(candidates))
            elif candidates:
                phi = self._variable(name, node, "phi")
                for candidate in sorted(candidates):
                    self.program.add_edge(candidate, phi, "phi")
                candidate_types = {
                    inferred_type
                    for candidate in candidates
                    for inferred_type in self.node_types.get(candidate, ())
                }
                if candidate_types:
                    self.node_types[phi] = frozenset(candidate_types)
                self.environment[name] = phi
        for access_path in sorted(
            set().union(*(outcome.keys() for outcome in field_outcomes))
        ):
            candidates = {
                outcome.get(access_path, before_fields.get(access_path))
                for outcome in field_outcomes
            }
            candidates.discard(None)
            if len(candidates) == 1:
                self.fields[access_path] = next(iter(candidates))
            elif candidates:
                phi = self._node("phi", node, f"{access_path}#phi")
                for candidate in sorted(candidates):
                    self.program.add_edge(candidate, phi, "phi")
                candidate_types = {
                    inferred_type
                    for candidate in candidates
                    for inferred_type in self.node_types.get(candidate, ())
                }
                if candidate_types:
                    self.node_types[phi] = frozenset(candidate_types)
                self.fields[access_path] = phi
        return True

    def _assign(self, target: ast.expr, value: str | None) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, value)
            return
        if isinstance(target, ast.Name):
            destination = self._variable(target.id, target, "variable")
            self.environment[target.id] = destination
        elif isinstance(target, ast.Attribute):
            access_path = self._attribute_path(target)
            destination = self._node("field", target, access_path or target.attr)
            if access_path is not None:
                self.fields[access_path] = destination
        else:
            destination = self._node("field", target, _expression_name(target) or "field")
        if value is not None:
            self.program.add_edge(value, destination, "assignment")
            if value in self.node_types:
                self.node_types[destination] = self.node_types[value]
            self.object_ids[destination] = self.object_ids.get(value, value)

    def _expression(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            if node.id in self.environment:
                return self.environment[node.id]
            symbol = self._resolve_name(node.id)
            return self._node("reference", node, node.id, symbol)
        if isinstance(node, ast.Constant):
            result = self._node("literal", node, repr(node.value))
            if isinstance(node.value, (str, bytes, int, float, bool)):
                self.node_types[result] = frozenset(
                    (f"builtins.{type(node.value).__name__}",)
                )
            return result
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            access_path = self._attribute_path(node)
            if access_path is not None and access_path in self.fields:
                return self.fields[access_path]
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            return self._subscript(node)
        if isinstance(node, ast.NamedExpr):
            value = self._expression(node.value)
            self._assign(node.target, value)
            return value
        if isinstance(node, ast.IfExp):
            self._expression(node.test)
            result = self._node("expression", node, "conditional")
            body = self._expression(node.body)
            otherwise = self._expression(node.orelse)
            self.program.add_edge(body, result, "branch")
            self.program.add_edge(otherwise, result, "branch")
            possible_types = self.node_types.get(body, frozenset()) | self.node_types.get(
                otherwise, frozenset()
            )
            if possible_types:
                self.node_types[result] = possible_types
            return result

        result = self._node("expression", node, type(node).__name__)
        children: list[str] = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr) and child is not getattr(node, "ctx", None):
                child_node = self._expression(child)
                children.append(child_node)
                self.program.add_edge(child_node, result, "expression")
        if isinstance(node, ast.JoinedStr):
            self.node_types[result] = frozenset(("builtins.str",))
        elif isinstance(node, ast.Dict):
            self.node_types[result] = frozenset(("builtins.dict",))
        elif isinstance(node, (ast.List, ast.ListComp)):
            self.node_types[result] = frozenset(("builtins.list",))
        elif isinstance(node, ast.BinOp):
            child_types = {
                inferred_type
                for item in children
                for inferred_type in self.node_types.get(item, ())
            }
            if (
                children
                and all(item in self.node_types for item in children)
                and len(child_types) == 1
            ):
                self.node_types[result] = frozenset(child_types)
        return result

    def _subscript(self, node: ast.Subscript) -> str:
        raw_receiver = _expression_name(node.value) or "<dynamic>"
        callee = f"{self._resolve_name(raw_receiver)}.__getitem__"
        receiver = self._expression(node.value)
        argument = self._expression(node.slice)
        result = self._node("call_result", node, f"{callee}()", callee)
        self.object_ids[result] = result
        if callee in EXTERNAL_RETURN_TYPES:
            self.node_types[result] = frozenset((EXTERNAL_RETURN_TYPES[callee],))
        self.program.calls.append(
            CallSite(
                callee=callee,
                scope=self.source.symbol,
                location=self._location(node),
                result_node=result,
                positional_arguments=(argument,),
                receiver_node=receiver,
            )
        )
        return result

    def _attribute_path(self, node: ast.Attribute) -> str | None:
        receiver = self._expression(node.value)
        identity = self.object_ids.get(receiver, receiver)
        return f"{identity}.{node.attr}"

    def _call(self, node: ast.Call) -> str:
        raw_callee = _expression_name(node.func) or "<dynamic>"
        receiver = (
            self._expression(node.func.value) if isinstance(node.func, ast.Attribute) else None
        )
        receiver_types = self.node_types.get(receiver, frozenset()) if receiver else frozenset()
        if receiver_types and isinstance(node.func, ast.Attribute):
            callees = tuple(
                sorted(
                    {
                        self._resolve_method(receiver_type, node.func.attr)
                        or f"{receiver_type}.{node.func.attr}"
                        for receiver_type in receiver_types
                    }
                )
            )
        else:
            callees = (self._resolve_name(raw_callee),)
        positional_arguments = tuple(self._expression(argument) for argument in node.args)
        keyword_arguments = tuple(
            (keyword.arg, self._expression(keyword.value)) for keyword in node.keywords
        )
        keyword_values = tuple(
            (keyword.arg, keyword.value.value)
            for keyword in node.keywords
            if keyword.arg is not None and isinstance(keyword.value, ast.Constant)
        )
        symbol = callees[0] if len(callees) == 1 else raw_callee
        result = self._node("call_result", node, f"{symbol}()", symbol)
        self.object_ids[result] = result
        return_types = {
            return_type
            for callee in callees
            for return_type in (
                (callee,) if callee in self.program.classes else ()
            )
        }
        return_types.update(
            EXTERNAL_RETURN_TYPES[callee]
            for callee in callees
            if callee in EXTERNAL_RETURN_TYPES
        )
        if return_types:
            self.node_types[result] = frozenset(return_types)
        for callee in callees:
            self.program.calls.append(
                CallSite(
                    callee=callee,
                    scope=self.source.symbol,
                    location=self._location(node),
                    result_node=result,
                    positional_arguments=positional_arguments,
                    keyword_arguments=keyword_arguments,
                    keyword_values=keyword_values,
                    receiver_node=receiver,
                    possible_dispatch=len(callees) > 1,
                )
            )
        return result

    def _resolve_name(self, name: str) -> str:
        head, separator, tail = name.partition(".")
        imported = self.program.imports.get(self.source.module, {}).get(head)
        if imported:
            return imported + (separator + tail if tail else "")
        local = f"{self.source.module}.{name}"
        if local in self.program.defined_symbols:
            return local
        if name in {"input", "eval", "exec", "open", "str"}:
            return f"builtins.{name}"
        return name

    def _resolve_method(self, class_symbol: str, method: str) -> str | None:
        pending = [class_symbol]
        visited: set[str] = set()
        while pending:
            current = pending.pop(0)
            if current in visited:
                continue
            visited.add(current)
            candidate = f"{current}.{method}"
            if candidate in self.program.defined_symbols:
                return candidate
            class_ir = self.program.classes.get(current)
            if class_ir:
                pending.extend(class_ir.bases)
        return None

    def _parameter_type(self, argument: ast.arg, position: int) -> str | None:
        if self.source.owner_class and position == 0 and self.source.binding in {"instance", "class"}:
            return self.source.owner_class
        if argument.annotation is None:
            return None
        name = _expression_name(argument.annotation)
        if name is None:
            return None
        resolved = self._resolve_name(name)
        return resolved if resolved in self.program.classes else None

    def _variable(self, name: str, node: ast.AST, kind: str) -> str:
        version = self.versions.get(name, 0) + 1
        self.versions[name] = version
        return self._node(kind, node, f"{name}#{version}", f"{self.source.symbol}:{name}")

    def _node(self, kind: str, node: ast.AST, label: str, symbol: str | None = None) -> str:
        self.counter += 1
        location = self._location(node)
        identifier = (
            f"{location.path}:{location.line}:{location.col}:"
            f"{self.source.symbol}:{kind}:{self.counter}"
        )
        return self.program.add_node(
            FlowNode(id=identifier, kind=kind, label=label, location=location, symbol=symbol)
        )

    def _location(self, node: ast.AST) -> Location:
        return Location.from_ast(self.program.root, self.source.path, node)


def _expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _connect_calls(program: ProgramIR) -> None:
    for call in program.calls:
        function = program.functions.get(call.callee)
        if function is None:
            continue
        edge_prefix = "possible_" if call.possible_dispatch else ""
        parameter_offset = 0
        if (
            call.receiver_node
            and function.binding in {"instance", "class"}
            and function.parameter_nodes
        ):
            program.add_edge(
                call.receiver_node,
                function.parameter_nodes[0],
                f"{edge_prefix}receiver_to_parameter",
            )
            parameter_offset = 1
        for argument, parameter in zip(
            call.positional_arguments,
            function.parameter_nodes[parameter_offset:],
            strict=False,
        ):
            program.add_edge(argument, parameter, f"{edge_prefix}argument_to_parameter")
        parameters = dict(zip(function.parameters, function.parameter_nodes, strict=True))
        for name, argument in call.keyword_arguments:
            if name in parameters:
                program.add_edge(
                    argument,
                    parameters[name],
                    f"{edge_prefix}keyword_to_parameter",
                )
        program.add_edge(
            function.return_node,
            call.result_node,
            f"{edge_prefix}return_to_call",
        )
