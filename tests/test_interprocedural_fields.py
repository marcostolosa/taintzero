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

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert not any(diagnostic.startswith("heap-") for diagnostic in program.diagnostics)


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

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert not any(diagnostic.startswith("heap-") for diagnostic in program.diagnostics)


def test_heap_phi_connects_branch_definitions_to_method_load(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "class Holder:\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route(flag):\n"
        "    holder = Holder()\n"
        "    if flag:\n"
        "        holder.command = request.args.get('command')\n"
        "    else:\n"
        "        holder.command = 'constant'\n"
        "    holder.run()\n",
    )

    program = index_python_project(tmp_path)
    findings = analyze_taint(program)

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert any(step.node.kind == "phi" for step in findings[0].trace)
    assert any(step.incoming_edge == "possible_field_store_to_load" for step in findings[0].trace)


def test_heap_phi_with_sanitized_branches_is_safe(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "from shlex import quote\n"
        "class Holder:\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route(flag):\n"
        "    holder = Holder()\n"
        "    if flag:\n"
        "        holder.command = quote(request.args.get('command'))\n"
        "    else:\n"
        "        holder.command = 'constant'\n"
        "    holder.run()\n",
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert not any(diagnostic.startswith("heap-") for diagnostic in program.diagnostics)


def test_multiple_setter_calls_are_specialized_by_instance(tmp_path: Path) -> None:
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
    findings = analyze_taint(program)

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert findings[0].confidence == "probable"
    assert len(
        [
            function
            for function in program.functions
            if function.startswith("app.Holder.set_command@")
        ]
    ) == 2


def test_context_clones_do_not_cross_contaminate_instances(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        _holder_program(
            "    first = Holder()\n"
            "    second = Holder()\n"
            "    first.set_command('constant')\n"
            "    second.set_command(request.args.get('command'))\n"
            "    first.run()\n"
        ),
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert not any(diagnostic.startswith("heap-") for diagnostic in program.diagnostics)


def test_nested_project_call_is_cloned_per_context(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "def normalize(value):\n"
        "    return value\n"
        "class Holder:\n"
        "    def set_command(self, value):\n"
        "        self.command = normalize(value)\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route():\n"
        "    first = Holder()\n"
        "    second = Holder()\n"
        "    first.set_command(request.args.get('command'))\n"
        "    second.set_command('constant')\n"
        "    first.run()\n",
    )

    program = index_python_project(tmp_path)
    findings = analyze_taint(program)

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert len(
        [function for function in program.functions if function.startswith("app.normalize@")]
    ) == 2
    assert all(
        not diagnostic.startswith("heap-context-clone-unsupported:")
        for diagnostic in program.diagnostics
    )


def test_nested_contexts_do_not_cross_contaminate_instances(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "def normalize(value):\n"
        "    return value\n"
        "class Holder:\n"
        "    def set_command(self, value):\n"
        "        self.command = normalize(value)\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route():\n"
        "    first = Holder()\n"
        "    second = Holder()\n"
        "    first.set_command('constant')\n"
        "    second.set_command(request.args.get('command'))\n"
        "    first.run()\n",
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_recursive_context_expansion_is_blocked_and_diagnosed(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "def normalize(value):\n"
        "    return normalize(value)\n"
        "class Holder:\n"
        "    def set_command(self, value):\n"
        "        self.command = normalize(value)\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route():\n"
        "    first = Holder()\n"
        "    second = Holder()\n"
        "    first.set_command(request.args.get('command'))\n"
        "    second.set_command('constant')\n"
        "    first.run()\n",
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert "heap-context-recursion:app.normalize" in program.diagnostics


def test_context_expansion_depth_is_bounded_and_diagnosed(tmp_path: Path) -> None:
    _write_app(
        tmp_path,
        "import os\n"
        "from flask import request\n"
        "def h5(value):\n"
        "    return value\n"
        "def h4(value):\n"
        "    return h5(value)\n"
        "def h3(value):\n"
        "    return h4(value)\n"
        "def h2(value):\n"
        "    return h3(value)\n"
        "def h1(value):\n"
        "    return h2(value)\n"
        "class Holder:\n"
        "    def set_command(self, value):\n"
        "        self.command = h1(value)\n"
        "    def run(self):\n"
        "        os.system(self.command)\n"
        "def route():\n"
        "    first = Holder()\n"
        "    second = Holder()\n"
        "    first.set_command(request.args.get('command'))\n"
        "    second.set_command('constant')\n"
        "    first.run()\n",
    )

    program = index_python_project(tmp_path)

    assert analyze_taint(program) == []
    assert "heap-context-depth-exceeded:app.h4:limit=4" in program.diagnostics


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
