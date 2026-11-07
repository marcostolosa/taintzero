import os
import subprocess

from flask import request


def vulnerable_ping():
    host = request.args.get("host")
    # ruleid: taintzero.python.command-injection
    return os.system("ping -c 1 " + host)


def safe_ping():
    host = request.args.get("host")
    # ok: taintzero.python.command-injection
    return subprocess.run(["ping", "-c", "1", host], check=False)
