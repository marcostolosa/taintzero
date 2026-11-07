import os

from flask import request


def ping():
    host = request.args.get("host")
    # ruleid: taintzero.python.command-injection
    return os.system("ping -c 1 " + host)
