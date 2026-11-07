import subprocess

from flask import request


def ping():
    host = request.args.get("host")
    # ok: taintzero.python.command-injection
    return subprocess.run(["ping", "-c", "1", host], check=False)
