import subprocess, shlex
def ping_host(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
