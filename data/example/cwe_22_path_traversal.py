import os

class FileService:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir

    def build_path(self, name: str) -> str:
        # PROPAGATOR: tainted `name` joined into a path without validation
        return os.path.join(self.base_dir, name)

    def read_file(self, filename: str) -> str:
        # SOURCE: `filename` is user-controlled
        path = self.build_path(filename)  # PROPAGATOR
        with open(path, "r", encoding="utf-8") as fh:  # SINK: filesystem read
            return fh.read()

def read_user_file(base_dir: str, user_filename: str) -> str:
    # SOURCE: `user_filename` comes from user input
    svc = FileService(base_dir)
    return svc.read_file(user_filename)  # SINK via open()
