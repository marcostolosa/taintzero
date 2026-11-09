from flask import request
from service import execute


def route():
    command = request.args.get("command")
    execute(command)
