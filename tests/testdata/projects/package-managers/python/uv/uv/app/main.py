"""Minimal entrypoint with intentional insecure patterns for scanner validation."""

import os
import sqlite3


def load_config() -> dict:
    # Hardcoded fake credentials (secret finding)
    return {
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "github_token": "ghp_xxxxxxxxxxxxxxxxxxxx",
        "db_password": "password123",
    }


def lookup_user_raw(user_id: str) -> str:
    """First-party SQL injection pattern: unparameterized query."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    query = "SELECT name FROM users WHERE id = " + user_id
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return str(row)


def render_greeting(name: str) -> str:
    """First-party XSS-style pattern: unescaped interpolation."""
    return f"<h1>Hello, {name}</h1>"


if __name__ == "__main__":
    cfg = load_config()
    _ = os.environ.get("UNUSED", cfg["api_key"])
    print(render_greeting("World"))
