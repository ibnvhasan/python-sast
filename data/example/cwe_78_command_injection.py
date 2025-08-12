import subprocess

class SysAdmin:
    def __init__(self, count: int = 1) -> None:
        self.count = str(count)

    def build_cmd(self, host: str) -> str:
        # SOURCE: `host` is user-controlled
        # PROPAGATOR: concatenation into a shell command
        return "ping -c " + self.count + " " + host

    def run_ping(self, host: str) -> int:
        cmd = self.build_cmd(host)  # PROPAGATOR
        proc = subprocess.run(cmd, shell=True)  # SINK: shell execution
        return proc.returncode

def ping_host(host: str) -> int:
    # SOURCE: `host` comes from user input
    admin = SysAdmin()
    return admin.run_ping(host)  # SINK via subprocess.run(shell=True)
