from pathlib import Path

from taintzero.analysis import analyze_taint, index_python_project


def _write_app(root: Path, body: str) -> None:
    (root / "app.py").write_text(body, encoding="utf-8")


def _holder_program(route: str, *, setter: str = "self.command = value") -> str:
    return (
        "import os\n"
        "from flask import request\n"
        "from shlex import quote\n"
        "class Holder:\n"
        "    def set_command(self, value):\n"
        f"        {setter}\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route():\n"
        f"{route}"
    )


def test_field_flows_between_unique_method_calls(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    holder.set_command(request.args.get('command'))\n"
            "    holder.run()\n"
        ),
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert findings[0].confidence == "probable"
    assert any(
        step.incoming_edge == "possible_field_store_to_load"
        for step in findings[0].trace
    )


def test_field_does_not_cross_distinct_instances(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    source = Holder()\n"
            "    target = Holder()\n"
            "    source.set_command(request.args.get('command'))\n"
            "    target.run()\n"
        ),
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_explicit_object_alias_preserves_interprocedural_field(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    alias = holder\n"
            "    alias.set_command(request.args.get('command'))\n"
            "    holder.run()\n"
        ),
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]


def test_multiple_field_definitions_are_not_guessed(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    holder.command = request.args.get('command')\n"
            "    holder.command = 'constant'\n"
            "    holder.run()\n"
        ),
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert all(edge.kind != "possible_field_store_to_load" for edge in program.edges)
    assert any(
        diagnostic.startswith("heap-definitions-ambiguous:")
        for diagnostic in program.diagnostics
    )


def test_sanitizer_before_field_store_blocks_taint(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    holder.set_command(quote(request.args.get('command')))\n"
            "    holder.run()\n"
        ),
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_multiple_setter_calls_do_not_merge_instances(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    first = Holder()\n"
            "    second = Holder()\n"
            "    first.set_command(request.args.get('command'))\n"
            "    second.set_command('constant')\n"
            "    first.run()\n"
        ),
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert all(edge.kind != "possible_field_store_to_load" for edge in program.edges)
    assert any(
        diagnostic.startswith("heap-context-ambiguous:app.Holder.set_command:")
        for diagnostic in program.diagnostics
    )


def test_field_write_after_read_does_not_flow_backwards(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    holder.run()\n"
            "    holder.set_command(request.args.get('command'))\n"
        ),
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_interprocedural_field_graph_is_deterministic(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    holder = Holder()\n"
            "    holder.set_command(request.args.get('command'))\n"
            "    holder.run()\n"
        ),
    )

    first = index_python_project(tmp_path)
    second = index_python_project(tmp_path)

    assert first.object_aliases == second.object_aliases
    assert first.field_accesses == second.field_accesses
    assert first.edges == second.edges
    assert analyze_taint(first) == analyze_taint(second)
