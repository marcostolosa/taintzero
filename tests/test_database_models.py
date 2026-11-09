from pathlib import Path

from taintzero.analysis import analyze_taint, index_python_project


def test_module_database_cursor_type_flows_into_route(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "from flask import request\n"
        "connection = sqlite3.connect('app.db')\n"
        "cursor = connection.cursor()\n"
        "def route():\n"
        "    name = request.args.get('name')\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n",
        encoding="utf-8",
    )

    findings = analyze_taint(index_python_project(tmp_path))

    assert [finding.vulnerability for finding in findings] == ["sql-injection"]
    assert findings[0].sink.line == 7


def test_unrelated_execute_method_is_not_assumed_to_be_sql(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "class Worker:\n"
        "    def execute(self, value):\n"
        "        return value\n"
        "def route(worker: Worker):\n"
        "    worker.execute(request.args.get('value'))\n",
        encoding="utf-8",
    )

    assert analyze_taint(index_python_project(tmp_path)) == []
