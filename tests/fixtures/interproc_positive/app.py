from flask import request
from service import execute
from transform import normalize


def route():
    command = request.args.get("command")
    normalized = normalize(command)
    execute(normalized)
