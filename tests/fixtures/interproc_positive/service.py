import subprocess


def execute(command):
    subprocess.run(command, check=False, shell=True)
