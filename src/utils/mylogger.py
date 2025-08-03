"""
MyLogger - Compatible logger for model files
"""

import datetime
import os 

class MyLogger:
    """Logger compatible with the existing model implementations."""
    
    def __init__(self, logdir):
        self.logdir = logdir
        if logdir:
            os.makedirs(self.logdir, exist_ok=True)
            t = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self._logfile = f"{self.logdir}/log_{t}.txt"
        else:
            self._logfile = None

    def log(self, message, logtype="info", phase="", no_new_line=False, printonly=False):
        message = str(message)
        if len(phase) > 0:
            phase = f" [{phase}]"
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        s = f"[{logtype.upper()}] [{t}]{phase} {message}"
        
        if no_new_line:
            print(s, end="")
        else:
            print(s)
            
        if not printonly and self._logfile:
            try:
                with open(self._logfile, 'a') as f:
                    f.write(s)
                    f.write("\n")
            except Exception:
                pass  # Ignore file write errors

    def info(self, message, phase="", no_new_line=False):
        self.log(message, "info", phase, no_new_line=no_new_line)

    def error(self, message, phase=""):
        self.log(message, "error", phase)

    def debug(self, message, phase=""):
        self.log(message, "debug", phase)

    def warning(self, message, phase=""):
        self.log(message, "warning", phase)

    def print(self, message, end=None):
        print(message, end=end)
