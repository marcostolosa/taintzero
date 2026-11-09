from pathlib import Path

from taintzero.analysis import analyze_taint, index_python_project

FIXTURES = Path(__file__).parent / "fixtures"


def _write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_finds_cross_file_command_injection() -> None:
    program = index_python_project(FIXTURES / "interproc_positive")

    findings = analyze_taint(program)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability == "command-injection"
    assert finding.source.path == "app.py"
    assert finding.sink.path == "service.py"
    assert finding.confidence == "exact"
    assert any(step.incoming_edge == "argument_to_parameter" for step in finding.trace)
    assert any(step.incoming_edge == "return_to_call" for step in finding.trace)
    assert finding.trace[0].node.location.path == "app.py"
    assert finding.trace[-1].node.location.path == "service.py"


def test_sanitizer_stops_cross_file_taint() -> None:
    program = index_python_project(FIXTURES / "interproc_sanitized")

    assert analyze_taint(program) == []


def test_trace_serialization_is_stable() -> None:
    program = index_python_project(FIXTURES / "interproc_positive")

    result = analyze_taint(program)[0].to_dict()

    assert result["rule_id"] == "taintzero.python.command-injection"
    assert result["confidence"] == "exact"
    assert isinstance(result["trace"], list)


def test_index_is_deterministic() -> None:
    first = index_python_project(FIXTURES / "interproc_positive")
    second = index_python_project(FIXTURES / "interproc_positive")

    assert list(first.nodes) == list(second.nodes)
    assert first.edges == second.edges
    assert analyze_taint(first) == analyze_taint(second)


def test_argument_list_without_shell_is_not_command_injection() -> None:
    program = index_python_project(Path(__file__).parents[1] / "fixtures" / "repository")

    findings = analyze_taint(program)

    assert len(findings) == 1
    assert findings[0].sink.path == "vulnerable.py"


def test_resolves_keyword_arguments_by_parameter_name(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import execute\n"
            "def route():\n"
            "    execute(other='safe', command=request.args.get('command'))\n",
            "service.py": "import os\n"
            "def execute(other, command):\n"
            "    os.system(command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
    assert any(step.incoming_edge == "keyword_to_parameter" for step in findings[0].trace)


def test_resolves_relative_import_across_package(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "package/__init__.py": "",
            "package/app.py": "from flask import request\n"
            "from .service import execute\n"
            "def route():\n"
            "    execute(request.form.get('command'))\n",
            "package/service.py": "import os\n"
            "def execute(command):\n"
            "    os.system(command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
    assert findings[0].source.path == "package/app.py"
    assert findings[0].sink.path == "package/service.py"


def test_resolves_imported_class_method(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import Executor\n"
            "def route():\n"
            "    Executor.execute(request.args.get('command'))\n",
            "service.py": "import os\n"
            "class Executor:\n"
            "    @staticmethod\n"
            "    def execute(command):\n"
            "        os.system(command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
    assert findings[0].confidence == "exact"


def test_unknown_external_transformation_is_conservative(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "from unknown import transform\n"
            "def route():\n"
            "    value = transform(request.args.get('command'))\n"
            "    os.system(value)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
    assert findings[0].confidence == "probable"
    assert any(step.incoming_edge == "external_call" for step in findings[0].trace)


def test_branch_with_unsanitized_path_remains_vulnerable(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "import shlex\n"
            "from flask import request\n"
            "def route(is_admin):\n"
            "    command = request.args.get('command')\n"
            "    if is_admin:\n"
            "        selected = shlex.quote(command)\n"
            "    else:\n"
            "        selected = command\n"
            "    os.system(selected)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
    assert any(step.incoming_edge == "phi" for step in findings[0].trace)


def test_all_branch_outputs_sanitized_are_safe(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "import shlex\n"
            "from flask import request\n"
            "def route(flag):\n"
            "    command = request.args.get('command')\n"
            "    if flag:\n"
            "        selected = shlex.quote(command)\n"
            "    else:\n"
            "        selected = shlex.quote(command)\n"
            "    os.system(selected)\n",
        },
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_attribute_assignment_reaches_sink(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "class Holder:\n"
            "    pass\n"
            "def route():\n"
            "    holder = Holder()\n"
            "    holder.command = request.args.get('command')\n"
            "    os.system(holder.command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert any(step.node.kind == "field" for step in findings[0].trace)


def test_attribute_alias_preserves_object_identity(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "class Holder:\n"
            "    pass\n"
            "def route():\n"
            "    holder = Holder()\n"
            "    alias = holder\n"
            "    alias.command = request.args.get('command')\n"
            "    os.system(holder.command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]


def test_safe_attribute_overwrite_kills_previous_definition(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "class Holder:\n"
            "    pass\n"
            "def route():\n"
            "    holder = Holder()\n"
            "    holder.command = request.args.get('command')\n"
            "    holder.command = 'constant'\n"
            "    os.system(holder.command)\n",
        },
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_attribute_phi_preserves_vulnerable_branch(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "class Holder:\n"
            "    pass\n"
            "def route(flag):\n"
            "    holder = Holder()\n"
            "    if flag:\n"
            "        holder.command = request.args.get('command')\n"
            "    else:\n"
            "        holder.command = 'constant'\n"
            "    os.system(holder.command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["command-injection"]
    assert any(step.node.kind == "phi" for step in findings[0].trace)


def test_attribute_phi_with_safe_branches_remains_safe(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "import os\n"
            "from flask import request\n"
            "from shlex import quote\n"
            "class Holder:\n"
            "    pass\n"
            "def route(flag):\n"
            "    holder = Holder()\n"
            "    if flag:\n"
            "        holder.command = quote(request.args.get('command'))\n"
            "    else:\n"
            "        holder.command = 'constant'\n"
            "    os.system(holder.command)\n",
        },
    )

    assert analyze_taint(index_python_project(tmp_path)) == []


def test_partial_project_reports_syntax_error_and_keeps_scanning(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "broken.py": "def incomplete(\n",
            "app.py": "import os\n"
            "from flask import request\n"
            "def route():\n"
            "    os.system(request.args.get('command'))\n",
            ".venv/ignored.py": "def also_broken(\n",
        },
    )

    program = index_python_project(tmp_path)
    findings = analyze_taint(program)

    assert len(findings) == 1
    assert len(program.diagnostics) == 1
    assert program.diagnostics[0].startswith("broken.py:")
    assert all(".venv" not in diagnostic for diagnostic in program.diagnostics)


def test_resolves_instance_and_self_method_calls(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import Executor\n"
            "def route():\n"
            "    worker = Executor()\n"
            "    worker.dispatch(request.args.get('command'))\n",
            "service.py": "import os\n"
            "class Executor:\n"
            "    def dispatch(self, command):\n"
            "        self.execute(command)\n"
            "    def execute(self, command):\n"
            "        os.system(command)\n",
        },
    )

    program = index_python_project(tmp_path)
    findings = analyze_taint(program)

    assert len(findings) == 1
    assert findings[0].confidence == "exact"
    assert {call.callee for call in program.calls} >= {
        "service.Executor.dispatch",
        "service.Executor.execute",
    }


def test_resolves_inherited_instance_method(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import ShellExecutor\n"
            "def route():\n"
            "    worker = ShellExecutor()\n"
            "    worker.execute(request.args.get('command'))\n",
            "service.py": "import os\n"
            "class BaseExecutor:\n"
            "    def execute(self, command):\n"
            "        os.system(command)\n"
            "class ShellExecutor(BaseExecutor):\n"
            "    pass\n",
        },
    )

    program = index_python_project(tmp_path)
    findings = analyze_taint(program)

    assert len(findings) == 1
    assert any(call.callee == "service.BaseExecutor.execute" for call in program.calls)


def test_resolves_annotated_instance_parameter(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import Executor\n"
            "def route(worker: Executor):\n"
            "    worker.execute(request.args.get('command'))\n",
            "service.py": "import os\n"
            "class Executor:\n"
            "    def execute(self, command):\n"
            "        os.system(command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1


def test_resolves_method_on_inline_constructor(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "app.py": "from flask import request\n"
            "from service import Executor\n"
            "def route():\n"
            "    Executor().execute(request.args.get('command'))\n",
            "service.py": "import os\n"
            "class Executor:\n"
            "    def execute(self, command):\n"
            "        os.system(command)\n",
        },
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert len(findings) == 1
