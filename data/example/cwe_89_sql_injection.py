import sqlite3
from typing import Any, List

class UserRepo:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def build_query(self, username: str) -> str:
        # SOURCE: `username` is user-controlled
        # PROPAGATOR: inserted directly into SQL
        return f"SELECT id, username, email FROM users WHERE username = '{username}'"

    def find_user(self, username: str) -> List[Any]:
        sql = self.build_query(username)  # PROPAGATOR
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(sql)  # SINK: execution of tainted SQL
            return cur.fetchall()
        finally:
            conn.close()

def search_user(db_path: str, user_input: str):
    # SOURCE: `user_input` comes from user
    repo = UserRepo(db_path)
    return repo.find_user(user_input)  # SINK via cursor.execute
