import shlex
import subprocess


def execute(command):
    safe_command = shlex.quote(command)
    subprocess.run(safe_command, check=False, shell=True)
